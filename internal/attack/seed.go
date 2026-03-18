package attack

import (
	"context"
	"embed"
	"fmt"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed seeds/*.yaml
var seedFS embed.FS

// SeedStore loads the embedded seed corpus into the given store.
// It is idempotent — attacks with stable IDs are upserted, not duplicated.
func SeedStore(ctx context.Context, store Store) (int, error) {
	entries, err := seedFS.ReadDir("seeds")
	if err != nil {
		return 0, fmt.Errorf("reading embedded seeds dir: %w", err)
	}

	total := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}

		data, err := seedFS.ReadFile("seeds/" + entry.Name())
		if err != nil {
			return total, fmt.Errorf("reading seed file %s: %w", entry.Name(), err)
		}

		var sf SeedFile
		if err := yaml.Unmarshal(data, &sf); err != nil {
			return total, fmt.Errorf("parsing seed file %s: %w", entry.Name(), err)
		}

		now := time.Now()
		for i := range sf.Attacks {
			sf.Attacks[i].Category = sf.Category
			if sf.Attacks[i].CreatedAt.IsZero() {
				sf.Attacks[i].CreatedAt = now
			}
		}

		if err := store.Add(ctx, sf.Attacks); err != nil {
			return total, fmt.Errorf("seeding %s: %w", entry.Name(), err)
		}
		total += len(sf.Attacks)
	}
	return total, nil
}
