control <- read.table("src/com-diag-codex/Codex/dat/unittest-time-core-all.csv", header=TRUE, sep=",", quote="\"")
data <- log2(control[8]) - 12
data[2] <- log2(control[9]) - 6
data[3] <- control[5]
array <- data.matrix(data)
matrix <- matrix(nrow=7,ncol=21)
for (ii in seq(from=1,to=147,by=1)) matrix[array[ii,2] + 1,array[ii,1] + 1] <- array[ii,3]
log10 <- log10(matrix)
kilolog10 <- log10 * 1000
