package main

import "embed"

//go:embed static/templates/*
var TemplatesFS embed.FS

//go:embed static/css/* static/js/* static/logo.png
var StaticFS embed.FS

//go:embed ols-wpanel-optimizer/*
var PluginFS embed.FS
