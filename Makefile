.PHONY: build clean

PLUGIN_NAME := accuknox-plugin.so
GO_FILES := main.go

build:
	@echo "Building AccuKnox Bifrost plugin..."
	go mod tidy
	go build -buildmode=plugin -o $(PLUGIN_NAME) $(GO_FILES)
	@echo "Plugin built successfully: $(PLUGIN_NAME)"

clean:
	@echo "Cleaning up..."
	rm -f $(PLUGIN_NAME)
	@echo "Clean complete"