package web

import (
	"embed"
	"io/fs"
)

//go:embed templates/*
var TemplatesFS embed.FS

//go:embed css/* js/* logo.png
var StaticFS embed.FS

//go:embed plugins/ols-wpanel-optimizer/*
var pluginAssets embed.FS

// PluginFS preserves the deployed plugin paths while keeping its source under web/.
var PluginFS = pluginSubFS()

func pluginSubFS() fs.FS {
	assets, err := fs.Sub(pluginAssets, "plugins")
	if err != nil {
		panic(err)
	}
	return assets
}
