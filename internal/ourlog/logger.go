// ourlog wraps and sets up the promlog instance for the application
package ourlog

import (
	gklog "github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/common/promlog"
)

var (
	Default gklog.Logger
	Level   = &promlog.AllowedLevel{}
	Config  = &promlog.Config{Level: Level}
)

// Info log helper
func Info(kv ...interface{}) error {
	initLog()
	return gklog.With(level.Info(Default), "invoker", gklog.Caller(4)).Log(kv...)
}

// Error log helper
func Error(kv ...interface{}) error {
	initLog()
	return gklog.With(level.Error(Default), "invoker", gklog.Caller(4)).Log(kv...)
}

// Debug log helper
func Debug(kv ...interface{}) error {
	initLog()
	return gklog.With(level.Debug(Default), "invoker", gklog.Caller(4)).Log(kv...)
}

// populate our default logger with our options
func initLog() {
	if Default != nil {
		return
	}

	lg := promlog.New(Config)
	Default = lg
}
