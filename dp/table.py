import numpy as np
import pandas as pd
import random
import matplotlib.pyplot as plt

class Table:
    def __init__(self, size):
        self.dp = np.zeros(size)
        print(self.dp)
        self.ldp = np.zeros(size)
        print(self.ldp)
        self.size = size

    def rr(self):
        l = []
        while (random.random() >= 0.5):
            l.append(random.randint(0, self.size-1))
        
        return l

    def addDP(self, n):
        self.dp[n] += 1
    
    def addLDP(self, n):
        self.ldp[n] += 1

        rr_list = Table.rr(self)
        for l in rr_list:
            self.ldp[l] += 1
    
    def applyDP(self, ep):
        rng = np.random.default_rng()
        lap = rng.laplace(0., 1/ep, self.size)
        r = np.round(lap)

        self.dp = self.dp + 12 + r
    
    def printMax(self):
        print('Max(DP):', np.max(self.dp))
        print('Max(LDP):', np.max(self.ldp))
    
    def printMin(self):
        print('Min(DP):', np.min(self.dp))
        print('Min(LDP):', np.min(self.ldp))
    
    def printMean(self):
        print('Mean(DP):', np.mean(self.dp))
        print('Mean(LDP)', np.mean(self.ldp))
    
    def drawHistogram(self):
        fig = plt.figure()
        ax1 = fig.add_subplot(1,2,1)
        ax2 = fig.add_subplot(1,2,2)

        ax1.bar(np.arange(self.size), self.dp)
        ax1.set_title('volume histogram of DP')
        ax1.set_xlabel('keys')
        ax1.set_ylabel('volume')

        ax2.bar(np.arange(self.size), self.ldp)
        ax2.set_title('volume histogram of LDP')
        ax2.set_xlabel('keys')
        ax2.set_ylabel('volume')

        plt.show()

