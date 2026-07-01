package parsers

import "testing"

func TestParseNuGetPackagesLock(t *testing.T) {
	body := []byte(`{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.3, )",
        "resolved": "13.0.3",
        "contentHash": "aaa"
      },
      "Serilog": {
        "type": "Transitive",
        "resolved": "3.1.1",
        "contentHash": "bbb"
      },
      "OurInternalProject": {
        "type": "Project"
      }
    },
    "net6.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "resolved": "13.0.3"
      }
    }
  }
}`)
	got, err := Parse("packages.lock.json", body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertContains(t, got,
		"Newtonsoft.Json@13.0.3/nuget",
		"Serilog@3.1.1/nuget",
	)
	for _, d := range got {
		if d.Name == "OurInternalProject" {
			t.Fatalf("project reference must not be emitted: %+v", d)
		}
	}
	// Same name+version across two TFMs collapses to one entry.
	count := 0
	for _, d := range got {
		if d.Name == "Newtonsoft.Json" && d.Version == "13.0.3" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("Newtonsoft.Json deduped across TFMs should appear once, got %d", count)
	}
}

func TestParseCSProjAttributeAndElementVersion(t *testing.T) {
	body := []byte(`<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Serilog">
      <Version>3.1.1</Version>
    </PackageReference>
    <PackageReference Include="CentralPinned" />
  </ItemGroup>
</Project>
`)
	got, err := Parse("App.csproj", body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertContains(t, got,
		"Newtonsoft.Json@13.0.3/nuget",
		"Serilog@3.1.1/nuget",
	)
	// Unpinned reference (central package management) emits the
	// package with an empty version so downstream name-based
	// checks still fire.
	assertContains(t, got, "CentralPinned@/nuget")
}

func TestParseCSProjFSProjAlias(t *testing.T) {
	body := []byte(`<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="FSharp.Core" Version="8.0.100" />
  </ItemGroup>
</Project>
`)
	got, err := Parse("Library.fsproj", body)
	if err != nil {
		t.Fatalf("Parse fsproj: %v", err)
	}
	assertContains(t, got, "FSharp.Core@8.0.100/nuget")
}
