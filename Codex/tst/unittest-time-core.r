core <- read.table("src/com-diag-codex/Codex/dat/unittest-time-core-all.csv", header=TRUE, sep=",", quote="\"")
coredata <- log2(core[8]) - 12
coredata[2] <- log2(core[9]) - 6
coredata[3] <- core[5]
corearray <- data.matrix(coredata)
corematrix <- matrix(nrow=7,ncol=21)
for (ii in seq(from=1,to=147,by=1)) corematrix[corearray[ii,2] + 1,corearray[ii,1] + 1] <- corearray[ii,3]
rownames(corematrix) <- c("64", "128", "256", "512", "1024", "2048", "4096")
colnames(corematrix) <- c("4096", "8192", "16384", "32768", "65536", "131072", "262144", "524288", "1048576", "2097152", "4194304", "8388608", "16777216", "33554432", "67108864", "134217728", "268435456", "536870912", "1073741824", "2147483648", "4294967296")
write.table(corematrix, file = "src/com-diag-codex/Codex/dat/unittest-time-core-matrix.csv", quote = TRUE, sep = ",", eol = "\n", dec = ".", row.names = FALSE, col.names = FALSE)
corelog10 = log10(corematrix)
heatmap(corelog10, Rowv=NA, Colv=NA, main="Core log10 CPU Seconds", xlab="Data Bytes", ylab="Buffer Bytes", zlim=c(-3,3))
