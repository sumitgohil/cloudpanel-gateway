package gateway

import "testing"

func TestValidateCronSchedule(t *testing.T) {
	valid := CronRequest{Minute: "*/5", Hour: "0,12", Day: "1-5", Month: "1,6", Weekday: "1-5"}
	if err := validateCronSchedule(valid); err != nil {
		t.Fatalf("valid schedule rejected: %v", err)
	}
	for _, field := range []CronRequest{
		{Minute: "60", Hour: "*", Day: "*", Month: "*", Weekday: "*"},
		{Minute: "@daily", Hour: "*", Day: "*", Month: "*", Weekday: "*"},
		{Minute: "*\nMAILTO=x", Hour: "*", Day: "*", Month: "*", Weekday: "*"},
		{Minute: "*", Hour: "*", Day: "*", Month: "13", Weekday: "*"},
	} {
		if err := validateCronSchedule(field); err == nil {
			t.Fatalf("invalid schedule accepted: %#v", field)
		}
	}
}

func TestRenderCronFile(t *testing.T) {
	got := string(renderCronFile([]cronLine{{Minute: "0", Hour: "4", Day: "*", Month: "*", Weekday: "*", User: "wp1", Command: "'/usr/bin/php8.3' '/home/wp1/htdocs/site/task.php'"}}))
	want := "MAILTO=\"\"\n0 4 * * * wp1 '/usr/bin/php8.3' '/home/wp1/htdocs/site/task.php'\n"
	if got != want {
		t.Fatalf("rendered cron file mismatch:\nwant %q\n got %q", want, got)
	}
}

func TestShellQuote(t *testing.T) {
	got := shellQuote("a'b")
	if got != "'a'\\''b'" {
		t.Fatalf("unexpected shell quote: %q", got)
	}
}
