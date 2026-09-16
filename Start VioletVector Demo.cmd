@echo off
title VioletVector AI - Guided Demo
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\start-demo.ps1"
if errorlevel 1 (
  echo.
  echo Demo startup failed. Read the message above and docs\INSTALL.md.
  pause
)
