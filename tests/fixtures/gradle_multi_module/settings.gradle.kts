rootProject.name = "fixture-multi"

// multi-arg form on one call, plus a single-arg call
include(":mod-a", ":mod-b")
include(":mod-c")
