control <- read.table("src/com-diag-codex/Codex/dat/unittest-time-control-all.csv", header=TRUE, sep=",", quote="\"")
contdata <- log2(control[8]) - 12
contdata[2] <- log2(control[9]) - 6
contdata[3] <- control[5]
contarray <- data.matrix(contdata)
contmatrix <- matrix(nrow=7,ncol=21)
for (ii in seq(from=1,to=147,by=1)) contmatrix[contarray[ii,2] + 1,contarray[ii,1] + 1] <- contarray[ii,3]
rownames(contmatrix) <- c("64", "128", "256", "512", "1024", "2048", "4096")
colnames(contmatrix) <- c("4096", "8192", "16384", "32768", "65536", "131072", "262144", "524288", "1048576", "2097152", "4194304", "8388608", "16777216", "33554432", "67108864", "134217728", "268435456", "536870912", "1073741824", "2147483648", "4294967296")
write.table(contmatrix, file = "src/com-diag-codex/Codex/dat/unittest-time-control-matrix.csv", quote = TRUE, sep = ",", eol = "\n", dec = ".", row.names = FALSE, col.names = FALSE)
contlog10 = log10(contmatrix)
heatmap(contlog10, Rowv=NA, Colv=NA, main="Control log10 CPU Seconds", xlab="Data Bytes", ylab="Buffer Bytes", zlim=c(-3,3))
