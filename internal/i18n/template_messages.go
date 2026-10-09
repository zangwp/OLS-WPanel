package i18n

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	texttemplate "text/template"
	"text/template/parse"
)

// TemplateMessages holds immutable, precomputed JavaScript translation objects.
// It contains translation strings only, never template source or request data.
type TemplateMessages struct {
	pages    map[string]map[string]template.JS
	fallback map[string]template.JS
}

type templateMessageSource struct {
	namespaces   map[string]bool
	dependencies map[string]bool
	base         bool
}

// Match both literal keys and prefixes such as 'website.status_' + state.
// Selecting their namespace keeps dynamically composed keys available.
var templateMessageNamespace = regexp.MustCompile("[\"'`]([a-zA-Z][a-zA-Z0-9_]*)\\.[a-zA-Z0-9_]*")

// NewTemplateMessages discovers namespaces in the actual HTML templates and
// their partial/script dependencies, then serializes each locale once. The
// exposed key list remains the allowlist. Base's content dispatcher is skipped
// during dependency traversal so one page cannot pull in every other page.
func NewTemplateMessages(templatesFS fs.FS, exposedKeys []string) (*TemplateMessages, error) {
	if templatesFS == nil {
		return nil, fmt.Errorf("translation templates filesystem unavailable")
	}
	sources := map[string]templateMessageSource{}
	owners := map[string]string{}
	aliases := map[string]string{}
	err := fs.WalkDir(templatesFS, ".", func(file string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(file, ".html") {
			return nil
		}
		data, err := fs.ReadFile(templatesFS, file)
		if err != nil {
			return err
		}
		parsed, err := texttemplate.New(path.Base(file)).Funcs(texttemplate.FuncMap(FuncMap())).Parse(string(data))
		if err != nil {
			return fmt.Errorf("parse translation template %s: %w", file, err)
		}
		source := templateMessageSource{namespaces: map[string]bool{}, dependencies: map[string]bool{}}
		for _, match := range templateMessageNamespace.FindAllSubmatch(data, -1) {
			source.namespaces[string(match[1])] = true
		}
		var contentNames []string
		for _, unit := range parsed.Templates() {
			if unit.Tree == nil {
				continue
			}
			name := unit.Name()
			if old, duplicate := owners[name]; duplicate && old != file {
				return fmt.Errorf("duplicate translation template %s", name)
			}
			owners[name] = file
			if name == "base" {
				source.base = true
			}
			if strings.HasSuffix(name, "_content") {
				contentNames = append(contentNames, name)
			}
			collectTemplateMessageDependencies(unit.Tree.Root, source.dependencies)
		}
		sources[file] = source
		alias := strings.TrimSuffix(path.Base(file), ".html")
		if len(contentNames) == 1 {
			aliases[alias] = contentNames[0]
		} else {
			aliases[alias] = path.Base(file)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("translation HTML templates unavailable")
	}

	keys := make([]string, 0, len(exposedKeys))
	seenKeys := map[string]bool{}
	for _, key := range exposedKeys {
		if !seenKeys[key] {
			keys = append(keys, key)
			seenKeys[key] = true
		}
	}
	sort.Strings(keys)
	catalog := &TemplateMessages{pages: map[string]map[string]template.JS{}, fallback: map[string]template.JS{}}
	for _, lang := range []string{DefaultLang, English} {
		catalog.pages[lang] = map[string]template.JS{}
		catalog.fallback[lang] = marshalTemplateMessages(lang, keys)
	}
	for name, owner := range owners {
		namespaces := map[string]bool{"common": true, "auth": true, "nav": true, "app": true}
		visited := map[string]bool{}
		var visit func(string)
		visit = func(file string) {
			if visited[file] {
				return
			}
			visited[file] = true
			source := sources[file]
			for namespace := range source.namespaces {
				namespaces[namespace] = true
			}
			for dependency := range source.dependencies {
				if source.base && strings.HasSuffix(dependency, "_content") {
					continue
				}
				if dependencyOwner, exists := owners[dependency]; exists {
					visit(dependencyOwner)
				}
			}
		}
		visit(owner)
		selected := make([]string, 0, len(keys))
		for _, key := range keys {
			namespace, _, _ := strings.Cut(key, ".")
			if namespaces[namespace] || key == "dashboard.close" {
				selected = append(selected, key)
			}
		}
		for _, lang := range []string{DefaultLang, English} {
			catalog.pages[lang][name] = marshalTemplateMessages(lang, selected)
		}
	}
	for alias, name := range aliases {
		for _, lang := range []string{DefaultLang, English} {
			catalog.pages[lang][alias] = catalog.pages[lang][name]
		}
	}
	return catalog, nil
}

// JSON does no parsing or serialization on the request path. Unknown template
// names retain the full exposed catalog rather than silently losing messages.
func (c *TemplateMessages) JSON(lang, contentTemplate string) template.JS {
	if c == nil {
		return template.JS("{}")
	}
	lang = NormalizeLang(lang)
	if data, known := c.pages[lang][contentTemplate]; known {
		return data
	}
	return c.fallback[lang]
}

func marshalTemplateMessages(lang string, keys []string) template.JS {
	// encoding/json retains HTML escaping and U+2028/U+2029 escaping even though
	// the result is trusted for embedding inside the inline bootstrap script.
	data, _ := json.Marshal(ExposedMessages(lang, keys))
	return template.JS(data)
}

func collectTemplateMessageDependencies(node parse.Node, result map[string]bool) {
	if node == nil {
		return
	}
	switch node := node.(type) {
	case *parse.ListNode:
		if node == nil {
			return
		}
		for _, child := range node.Nodes {
			collectTemplateMessageDependencies(child, result)
		}
	case *parse.TemplateNode:
		result[node.Name] = true
	case *parse.IfNode:
		collectTemplateMessageDependencies(node.List, result)
		collectTemplateMessageDependencies(node.ElseList, result)
	case *parse.RangeNode:
		collectTemplateMessageDependencies(node.List, result)
		collectTemplateMessageDependencies(node.ElseList, result)
	case *parse.WithNode:
		collectTemplateMessageDependencies(node.List, result)
		collectTemplateMessageDependencies(node.ElseList, result)
	}
}
