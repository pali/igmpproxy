# Elapsed-time callout aging

Separate the interface-rescan timeout cap from callout aging. Rebuild the
pselect timeout pointer each wait, carry fractional monotonic time, account
for callback time, and advance old timers before accepting reports that create
new timers. Empty/refilled queues and interrupted waits must remain valid.
No IGMP protocol interval, interface configuration or routing policy changes.

The existing fixture `tests/test-igmpproxy-time.py SOURCE_TREE` compiles the
actual timer helpers/callout queue with a controlled clock and checks main-loop
ordering as a source contract. It is not a live IGMP timing or OS signal test.
It is retained from the downstream implementation and was not newly run here.

Exported on upstream master eb0aec2a508e21e7d87429ed24b2511a35a6a891.
The complete source patch applies and whitespace was checked. No new tests,
full daemon build or network/device access for this submission. Older deployed
downstream validation is not a new-baseline pass. Related issue 58 and older
proposals 32/59 remain credited as prior reports/work on the timer defect.
