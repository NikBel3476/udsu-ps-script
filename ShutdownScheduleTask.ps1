$taskName = "Shutdown pc"
$description = "Shuts pc down daily at 22:30"
$taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument 'Stop-Computer -Force'
$taskTrigger = New-ScheduledTaskTrigger -Daily -At 22:30

$existingTask = Get-ScheduledTask | Where-Object { $_.TaskName -like $taskName }

if ($existingTask) {
    write-host "-- Task with name '$taskName' already exists" -foregroundcolor Yellow
}
else {
    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $taskAction `
        -Trigger $taskTrigger `
        -Description $description
    write-host "-- Task '$taskName' created" -foregroundcolor Green
}
