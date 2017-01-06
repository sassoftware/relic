$project="relic"
candle -nologo -ext WixUtilExtension -arch x64 "$project.wxs"
if (!$?) {
    exit $LastExitCode
}
light -nologo -ext WixUtilExtension "$project.wixobj"
exit $LastExitCode
