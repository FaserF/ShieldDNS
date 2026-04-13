package main

import (
	"embed"
)

//go:embed www/*
var WebAssets embed.FS
