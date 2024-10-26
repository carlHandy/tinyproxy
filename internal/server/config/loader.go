package config

import (
    "gopkg.in/yaml.v3"
    "os"
)

func LoadConfig(path string) (*ServerConfig, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }

    config := NewServerConfig()
    err = yaml.Unmarshal(data, config)
    return config, err
}
