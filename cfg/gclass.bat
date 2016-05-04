@echo off
if "%1"=="" (
    echo 'Please give a file'
) else (
    grep "^[L][a-zA-Z0-9$/]*[;]$" %1
)
