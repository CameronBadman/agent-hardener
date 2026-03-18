package attack

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	chromem "github.com/philippgille/chromem-go"
)

// Store defines the interface for attack prompt storage and retrieval.
type Store interface {
	Add(ctx context.Context, attacks []AttackPrompt) error
	Query(ctx context.Context, category string, n int) ([]AttackPrompt, error)
	SimilaritySearch(ctx context.Context, text string, n int, threshold float64) ([]AttackPrompt, error)
	UpdateMetadata(ctx context.Context, id string, metadata map[string]string) error
	Count(ctx context.Context) (int, error)
}

const collectionName = "attacks"

// ChromemStore wraps chromem-go to implement Store.
type ChromemStore struct {
	db         *chromem.DB
	collection *chromem.Collection
	embedFunc  chromem.EmbeddingFunc
}

// NewChromemStore opens (or creates) an on-disk chromem-go DB.
func NewChromemStore(path string, embedFunc chromem.EmbeddingFunc) (*ChromemStore, error) {
	db, err := chromem.NewPersistentDB(path, false)
	if err != nil {
		return nil, fmt.Errorf("opening chromem db at %s: %w", path, err)
	}

	col, err := db.GetOrCreateCollection(collectionName, nil, embedFunc)
	if err != nil {
		return nil, fmt.Errorf("getting/creating collection: %w", err)
	}

	return &ChromemStore{db: db, collection: col, embedFunc: embedFunc}, nil
}

// Add upserts attacks into the vector store.
func (s *ChromemStore) Add(ctx context.Context, attacks []AttackPrompt) error {
	docs := make([]chromem.Document, 0, len(attacks))
	for _, a := range attacks {
		if a.CreatedAt.IsZero() {
			a.CreatedAt = time.Now()
		}
		meta := attackToMetadata(a)
		docs = append(docs, chromem.Document{
			ID:       a.ID,
			Content:  a.Text,
			Metadata: meta,
		})
	}

	for _, doc := range docs {
		if err := s.collection.AddDocument(ctx, doc); err != nil {
			// If document already exists, update metadata instead
			if strings.Contains(err.Error(), "already exists") {
				if updateErr := s.UpdateMetadata(ctx, doc.ID, doc.Metadata); updateErr != nil {
					return fmt.Errorf("updating existing document %s: %w", doc.ID, updateErr)
				}
				continue
			}
			return fmt.Errorf("adding document %s: %w", doc.ID, err)
		}
	}
	return nil
}

// Query returns up to n attacks filtered by category.
func (s *ChromemStore) Query(ctx context.Context, category string, n int) ([]AttackPrompt, error) {
	// chromem requires n <= collection size
	total := s.collection.Count()
	if total == 0 {
		return nil, nil
	}
	if n > total {
		n = total
	}

	// Use the category name as the query text so we get semantically relevant results
	queryText := category
	if queryText == "" {
		queryText = "adversarial attack prompt"
	}

	var where map[string]string
	if category != "" {
		where = map[string]string{"category": category}
	}

	results, err := s.collection.Query(ctx, queryText, n, where, nil)
	if err != nil {
		return nil, fmt.Errorf("querying category %q: %w", category, err)
	}

	attacks := make([]AttackPrompt, 0, len(results))
	for _, r := range results {
		attacks = append(attacks, metadataToAttack(r.ID, r.Content, r.Metadata))
	}
	return attacks, nil
}

// SimilaritySearch finds the n most similar attacks to the given text.
func (s *ChromemStore) SimilaritySearch(ctx context.Context, text string, n int, threshold float64) ([]AttackPrompt, error) {
	total := s.collection.Count()
	if total == 0 {
		return nil, nil
	}
	if n > total {
		n = total
	}
	results, err := s.collection.Query(ctx, text, n, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("similarity search: %w", err)
	}

	attacks := make([]AttackPrompt, 0)
	for _, r := range results {
		if float64(r.Similarity) >= threshold {
			attacks = append(attacks, metadataToAttack(r.ID, r.Content, r.Metadata))
		}
	}
	return attacks, nil
}

// UpdateMetadata updates the stored metadata for an existing attack.
func (s *ChromemStore) UpdateMetadata(ctx context.Context, id string, metadata map[string]string) error {
	doc, err := s.collection.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("getting document %s: %w", id, err)
	}

	// Merge new metadata over existing
	merged := make(map[string]string)
	for k, v := range doc.Metadata {
		merged[k] = v
	}
	for k, v := range metadata {
		merged[k] = v
	}

	updated := chromem.Document{
		ID:       doc.ID,
		Content:  doc.Content,
		Metadata: merged,
	}
	// Delete and re-add to update
	if err := s.collection.Delete(ctx, nil, nil, id); err != nil {
		return fmt.Errorf("deleting document for update %s: %w", id, err)
	}
	if err := s.collection.AddDocument(ctx, updated); err != nil {
		return fmt.Errorf("re-adding document %s: %w", id, err)
	}
	return nil
}

// Count returns the total number of stored attacks.
func (s *ChromemStore) Count(ctx context.Context) (int, error) {
	return s.collection.Count(), nil
}

func attackToMetadata(a AttackPrompt) map[string]string {
	tags := strings.Join(a.Tags, ",")
	return map[string]string{
		"category":   string(a.Category),
		"technique":  string(a.Technique),
		"target":     string(a.Target),
		"severity":   a.Severity,
		"tags":       tags,
		"parent_id":  a.ParentID,
		"generation": strconv.Itoa(a.Generation),
		"run_count":  strconv.Itoa(a.RunCount),
		"best_score": strconv.FormatFloat(a.BestScore, 'f', 4, 64),
		"created_at": a.CreatedAt.Format(time.RFC3339),
	}
}

func metadataToAttack(id, content string, meta map[string]string) AttackPrompt {
	a := AttackPrompt{
		ID:        id,
		Text:      content,
		Category:  CategoryFromString(meta["category"]),
		Technique: AttackTechnique(meta["technique"]),
		Target:    AttackTarget(meta["target"]),
		Severity:  meta["severity"],
		ParentID:  meta["parent_id"],
	}
	if tags := meta["tags"]; tags != "" {
		a.Tags = strings.Split(tags, ",")
	}
	if gen, err := strconv.Atoi(meta["generation"]); err == nil {
		a.Generation = gen
	}
	if rc, err := strconv.Atoi(meta["run_count"]); err == nil {
		a.RunCount = rc
	}
	if bs, err := strconv.ParseFloat(meta["best_score"], 64); err == nil {
		a.BestScore = bs
	}
	if t, err := time.Parse(time.RFC3339, meta["created_at"]); err == nil {
		a.CreatedAt = t
	}
	return a
}
