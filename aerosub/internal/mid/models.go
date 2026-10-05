// Copyright 2026 AERO Protocol Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package mid

// ServerConfig represents the edge node configuration contract in subscriptions
type ServerConfig struct {
	Name        string   `json:"name" yaml:"name"`
	Host        string   `json:"host,omitempty" yaml:"host"`
	Address     string   `json:"address" yaml:"addr"`
	IP          string   `json:"ip,omitempty" yaml:"ip"`
	Token       string   `json:"token" yaml:"token"`
	SNI         string   `json:"sni" yaml:"sni"`
	Protocol    string   `json:"protocol" yaml:"protocol"`
	PinSPKI     []string `json:"pin_spki,omitempty" yaml:"pin_spki"`
	PurityScore int      `json:"purityScore,omitempty"`
	AIBlocked   bool     `json:"aiBlocked,omitempty"`
	LineType    string   `json:"line_type,omitempty" yaml:"line_type"`
	ISPAffinity string   `json:"isp_affinity,omitempty" yaml:"isp_affinity"`
	AltPorts    []int    `json:"alt_ports,omitempty" yaml:"alt_ports"`
	ECH         string   `json:"ech,omitempty" yaml:"ech"`
}
