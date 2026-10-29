module github.com/sendscore/sendscore-app

go 1.26.0

require (
	github.com/emersion/go-smtp v0.25.0
	github.com/sendscore/sendscore v0.0.0
	modernc.org/sqlite v1.51.0
)

require (
	blitiri.com.ar/go/spf v1.6.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/emersion/go-msgauth v0.7.0 // indirect
	github.com/emersion/go-sasl v0.0.0-20241020182733-b788ff22d5a6 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	modernc.org/libc v1.72.3 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

// The engine is a private sibling repository until launch. Clone it next to
// this one (../sendscore).
replace github.com/sendscore/sendscore => ../sendscore
