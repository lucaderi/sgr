-- Chisel description
short_description = "Show the number of fork ( intercepting clone and execve ),  group by process name, on 1 sec interval "
category = "Process"

-- Chisel argument list

-- The number of items to show
TOP_NUMBER = 10
args = {}

-- Initialization callback
function on_init()
	chisel.exec("table_generator",
		"proc.name", 
		"Name",
		"evt.count",
		"Fork",
		"(evt.type=clone or evt.type=execve) and evt.dir=>", 
		"" .. TOP_NUMBER,
		"none")
	return true
end
