$proc = Start-Process dotnet -ArgumentList "build e:\Xray-core\Xray-dotnet\panel\NodePanel.Panel\NodePanel.Panel.csproj /tl:off /clp:ErrorsOnly" -NoNewWindow -PassThru -RedirectStandardOutput build_out.txt -RedirectStandardError build_err.txt
$proc.WaitForExit()
