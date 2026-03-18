package patcher

import (
	"fmt"
	"os"
	"strings"
)

// WriteHardenedConfig reads the original config file, replaces the
// system_prompt block with the hardened version, and writes a new file
// alongside the original named <basename>-hardened.<ext>.
//
// It never overwrites the original.
func WriteHardenedConfig(originalPath, hardenedPrompt string) (string, error) {
	data, err := os.ReadFile(originalPath)
	if err != nil {
		return "", fmt.Errorf("reading config: %w", err)
	}

	patched, err := replaceSystemPrompt(string(data), hardenedPrompt)
	if err != nil {
		return "", err
	}

	outPath := hardenedPath(originalPath)
	if err := os.WriteFile(outPath, []byte(patched), 0644); err != nil {
		return "", fmt.Errorf("writing hardened config: %w", err)
	}
	return outPath, nil
}

// hardenedPath derives the output path: foo.yaml → foo-hardened.yaml
func hardenedPath(original string) string {
	if idx := strings.LastIndex(original, "."); idx > 0 {
		return original[:idx] + "-hardened" + original[idx:]
	}
	return original + "-hardened"
}

// replaceSystemPrompt finds the system_prompt: | block in the YAML and
// replaces its content with the hardened prompt.
// This is a text-level replacement to preserve all other YAML formatting.
func replaceSystemPrompt(yamlContent, hardenedPrompt string) (string, error) {
	lines := strings.Split(yamlContent, "\n")

	startIdx := -1
	promptIndent := ""

	for i, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "system_prompt:") {
			startIdx = i
			promptIndent = line[:len(line)-len(trimmed)]
			break
		}
	}

	if startIdx == -1 {
		return "", fmt.Errorf("could not find system_prompt field in config")
	}

	// Find where the system_prompt block ends (next key at same or lower indent)
	endIdx := len(lines)
	for i := startIdx + 1; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			continue
		}
		// If indentation is same or less than the system_prompt key, it's a new field
		lineIndent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		if len(lineIndent) <= len(promptIndent) && strings.TrimSpace(line) != "" {
			endIdx = i
			break
		}
	}

	// Build the replacement block
	// Use literal block scalar (|) with the same indentation
	contentIndent := promptIndent + "  "
	var newBlock strings.Builder
	newBlock.WriteString(promptIndent + "system_prompt: |\n")
	for _, promptLine := range strings.Split(hardenedPrompt, "\n") {
		if promptLine == "" {
			newBlock.WriteString("\n")
		} else {
			newBlock.WriteString(contentIndent + promptLine + "\n")
		}
	}

	// Reconstruct the file
	var result strings.Builder
	for _, line := range lines[:startIdx] {
		result.WriteString(line + "\n")
	}
	result.WriteString(newBlock.String())
	for _, line := range lines[endIdx:] {
		result.WriteString(line + "\n")
	}

	return strings.TrimRight(result.String(), "\n") + "\n", nil
}
