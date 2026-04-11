savedcmd_proctrace.mod := printf '%s\n'   proctrace.o | awk '!x[$$0]++ { print("./"$$0) }' > proctrace.mod
