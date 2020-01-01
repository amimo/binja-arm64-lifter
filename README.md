# binja-arm64-lifter

这是一个Binary Ninja的ArchitectureHook插件,用于提升(lifting)一些还未被官方支持的arm64指令.

插件支持提升如下指令:

 - ccmp
 - cinc,csinc
 - ldar,stlr
 - ldrsw
 - umull

