default: build

# Default version empty
version := "${VERSION:-}"

release_path := "compile_artifacts"

mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
name := $(notdir $(patsubst %/,%,$(dir $(mkfile_path))))

ifeq ($(OS),Windows_NT)
	bin_suffix := ".exe"
else
	bin_suffix := ""
endif

clean:
	rm -f ./bin/$(name)*

compile: deps
	GOGC=off CGOENABLED=0 go build -i -o ./bin/$(name)$(bin_suffix) ./cmd

print-success:
	@echo
	@echo "Plugin built."
	@echo
	@echo "To use it, either run 'make install' or set your PATH environment variable correctly."

build: compile print-success

deps:
	go get

release: deps
	rm -rf $(release_path)
	mkdir $(release_path)
	GOOS=linux GOARCH=amd64 GOGC=off CGOENABLED=0 go build -i -o $(release_path)/$(name) ./cmd
	tar --remove-files -cvzf $(release_path)/$(name)-linux-amd64$(version).tar.gz -C $(release_path) $(name)

release-other: deps
	GOOS=darwin GOARCH=amd64 GOGC=off CGOENABLED=0 go build -i -o $(release_path)/$(name) ./cmd
	tar --remove-files -cvzf $(release_path)/$(name)-darwin-amd64$(version).tar.gz -C $(release_path) $(name)
	GOOS=windows GOARCH=amd64 GOGC=off CGOENABLED=0 go build -i -o $(release_path)/$(name).exe ./cmd
	tar --remove-files -cvzf $(release_path)/$(name)-windows-amd64$(version).tar.gz -C $(release_path) $(name).exe

install:
	cp bin/$(name) /usr/local/bin/


.PHONY : build release release-other install deps
