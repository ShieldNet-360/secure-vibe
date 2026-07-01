package scheduler

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
	"text/template"
	"time"
)

// TaskSchedulerTaskName is the Windows Task Scheduler task name. The CLI's
// scheduler subcommands create and remove tasks under this name.
const TaskSchedulerTaskName = "SkillsLibraryUpdate"

// Task Scheduler XML schema is documented at:
//
//	https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema
//
// The XML body is emitted as UTF-8 bytes (Go's default string encoding) and
// the declaration must match so strict parsers accept the file. Task
// Scheduler itself happens to accept either encoding, but a mismatched
// declaration is a latent compatibility hazard.
const taskSchedulerXMLTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Skills Library scheduled update</Description>
    <Author>secure-vibe</Author>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>{{ .Interval }}</Interval>
      </Repetition>
      <StartBoundary>2026-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{{ .Command }}</Command>
      <Arguments>{{ .Arguments }}</Arguments>
    </Exec>
  </Actions>
</Task>
`

// RenderTaskSchedulerXML produces the XML registration document for the
// scheduled task. text/template does not perform any escaping, so every
// caller-supplied value (Binary, each arg) is run through escapeXMLAttr
// first so it is safe to interpolate into the XML body.
func RenderTaskSchedulerXML(cfg Config) (string, error) {
	if cfg.Binary == "" {
		return "", fmt.Errorf("taskscheduler: Binary must be set")
	}
	if cfg.Interval <= 0 {
		return "", fmt.Errorf("taskscheduler: Interval must be positive")
	}
	args := cfg.Args
	if len(args) == 0 {
		args = []string{"update", "--regenerate", "--quiet"}
	}
	argString := strings.Builder{}
	for i, a := range args {
		if i > 0 {
			argString.WriteByte(' ')
		}
		argString.WriteString(escapeXMLAttr(a))
	}
	data := struct {
		Interval  string
		Command   string
		Arguments string
	}{
		Interval:  iso8601Duration(cfg.Interval),
		Command:   escapeXMLAttr(cfg.Binary),
		Arguments: argString.String(),
	}
	tpl := template.Must(template.New("task").Parse(taskSchedulerXMLTemplate))
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// iso8601Duration renders a Go duration as the ISO 8601 form Windows Task
// Scheduler requires. We only emit the minimal subset (hours and minutes).
func iso8601Duration(d time.Duration) string {
	if d <= 0 {
		return "PT1H"
	}
	hours := int(d / time.Hour)
	minutes := int(d % time.Hour / time.Minute)
	if hours == 0 && minutes == 0 {
		return "PT1M"
	}
	out := "PT"
	if hours > 0 {
		out += fmt.Sprintf("%dH", hours)
	}
	if minutes > 0 {
		out += fmt.Sprintf("%dM", minutes)
	}
	return out
}

// escapeXMLAttr escapes a single text value for inclusion in the rendered
// XML. We can't use html.EscapeString because Task Scheduler XML rejects
// &#x form numeric character references in attributes.
func escapeXMLAttr(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}
