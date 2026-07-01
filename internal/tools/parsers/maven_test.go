package parsers

import "testing"

func TestParsePomXMLEmitsRuntimeDeps(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>

  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.14.0</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.16.1</version>
      <scope>compile</scope>
    </dependency>
  </dependencies>

  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>3.11.0</version>
        <dependencies>
          <!-- A plugin-scoped dependency must NOT be emitted as a
               runtime artefact; the policy-check pipeline only
               cares about what ships at runtime. -->
          <dependency>
            <groupId>only-for-the-plugin</groupId>
            <artifactId>helper</artifactId>
            <version>1.0.0</version>
          </dependency>
        </dependencies>
      </plugin>
    </plugins>
  </build>
</project>
`)
	got, err := Parse("pom.xml", body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertContains(t, got,
		"org.apache.commons:commons-lang3@3.14.0/maven",
		"com.fasterxml.jackson.core:jackson-databind@2.16.1/maven",
	)
	// Plugin-internal dependency must not leak into the runtime list.
	for _, d := range got {
		if d.Name == "only-for-the-plugin:helper" {
			t.Fatalf("plugin-scoped dependency should not be emitted: %+v", d)
		}
	}
}

func TestParsePomXMLExclusionsDoNotOverwriteParentDep(t *testing.T) {
	// Regression: an <exclusions><exclusion> block inside a
	// <dependency> must not overwrite the parent dependency's
	// groupId / artifactId. The XML CharData handler used to
	// match purely on the leaf element name (groupId / artifactId)
	// while `insideDepSet` was still true throughout the entire
	// <dependency> scope, so the exclusion's coordinates would
	// silently replace the actual dependency's coordinates and
	// the scanner would chase the exclusion rather than the
	// dependency in the malicious-packages / typosquat database.
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>6.1.4</version>
      <exclusions>
        <exclusion>
          <groupId>commons-logging</groupId>
          <artifactId>commons-logging</artifactId>
        </exclusion>
      </exclusions>
    </dependency>
  </dependencies>
</project>
`)
	got, err := Parse("pom.xml", body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertContains(t, got, "org.springframework:spring-core@6.1.4/maven")
	for _, d := range got {
		if d.Name == "commons-logging:commons-logging" {
			t.Fatalf("exclusion coordinates leaked as a dependency: %+v", d)
		}
		if d.Name == "org.springframework:spring-core" && d.Version != "6.1.4" {
			t.Fatalf("parent dep version overwritten by exclusion: got %q want 6.1.4", d.Version)
		}
	}
}

func TestParsePomXMLAcceptsDependencyManagement(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.slf4j</groupId>
        <artifactId>slf4j-api</artifactId>
        <version>2.0.9</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
`)
	got, err := Parse("pom.xml", body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertContains(t, got, "org.slf4j:slf4j-api@2.0.9/maven")
}

func TestParseGradleLockfile(t *testing.T) {
	body := []byte(`# This is a Gradle lockfile.
# Do not modify by hand.
com.google.guava:guava:32.1.3-jre=runtimeClasspath
org.jetbrains.kotlin:kotlin-stdlib:1.9.22=compileClasspath,runtimeClasspath
empty=annotationProcessor
`)
	got, err := Parse("gradle.lockfile", body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertContains(t, got,
		"com.google.guava:guava@32.1.3-jre/maven",
		"org.jetbrains.kotlin:kotlin-stdlib@1.9.22/maven",
	)
	// `empty=` lines must not produce a dependency.
	for _, d := range got {
		if d.Name == "" || d.Version == "" {
			t.Fatalf("empty marker leaked into deps: %+v", d)
		}
	}
}

func TestParseGradleLockfileAcceptsBuildPrefix(t *testing.T) {
	body := []byte(`com.example:lib:1.0.0=runtimeClasspath
`)
	got, err := Parse("build.gradle.lockfile", body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertContains(t, got, "com.example:lib@1.0.0/maven")
}
