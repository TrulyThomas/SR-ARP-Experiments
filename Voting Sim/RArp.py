from http.client import OK
import math
from pickle import TRUE
import random
import time


class networkSystem:

    def __init__(self):
        self.subjects = []
        self.repGain = 1
        self.repLoss = 2
        self.votes = 0
        self.worngVotes = 0

    def run(self):
        i = 0
        while (i < 1000):
            self.tick()
            if(i % 100 == 0):
                print(self)

            i += 1
            time.sleep(0.05)

        print(self.votes)
        print(self.worngVotes)

    def __str__(self):
        pString = ""
        for subject in self.subjects:
            pString += f"{subject.name}|{subject.reputation}  "
        return pString

    def tick(self):
        OKGREEN = '\033[92m'
        WARNING = '\033[93m'
        ENDC = '\033[0m'

        votesTrue = 0
        arpTrue = 0
        votesFaulty = 0
        arpFaulty = 0

        index = math.floor(random.random() * len(self.subjects))
        arpMessage = self.subjects[index].arpMessage
        self.votes += 1

        faulty = 0
        faultyVote = []
        real = 0
        realVote = []

        for subject in self.subjects:
            vote = subject.ValidateArp(arpMessage, self.subjects[index].name)
            if vote == True:
                real += 1 * max(min(subject.reputation, 1000), 1)
                realVote.append(subject)
                votesTrue += 1
            else:
                faulty += 1 * max(min(subject.reputation, 1000), 1)
                faultyVote.append(subject)
                votesFaulty += 1

        message = f"It was {OKGREEN if arpMessage else WARNING}{arpMessage}{ENDC}"

        if real > faulty:
            self.reputationResult(realVote, faultyVote)
        else:
            # print(f"vote is {WARNING}False{ENDC} | {message}")
            self.reputationResult(faultyVote, realVote)
            self.subjects[index].reputation -= self.repLoss * 4

        if real > faulty:
            if arpMessage == False:
                self.worngVotes += 1
                print(f"vote is {OKGREEN}True{ENDC} | {message}")

        else:
            if arpMessage == True:
                self.worngVotes += 1
                print(f"vote is {WARNING}False{ENDC} | {message}")

    def reputationResult(self, wonVote, lostVote):
        for vote in wonVote:
            vote.reputation += self.repGain
        for vote in lostVote:
            vote.reputation -= self.repLoss


class subject:
    def __init__(self, reputation, name, chance, arpMessage):
        self.reputation = reputation
        self.name = name
        self.chance = chance
        self.arpMessage = arpMessage

    def ValidateArp(self, boolean, name):
        if name == self.name:
            return True

        if self.chance > random.random():
            return boolean
        return not boolean


network = networkSystem()
network.subjects.append(subject(0, "Thomas", 0.99, True))
network.subjects.append(subject(0, "Thor", 0.9, True))
network.subjects.append(subject(0, "Thor2", 0.85, True))
network.subjects.append(subject(0, "Thor3", 0.85, True))
network.subjects.append(subject(0, "Thor4", 0.85, True))
network.subjects.append(subject(0, "Malthe", 0.85, True))
network.subjects.append(subject(0, "Johan", 0.9, False))
# network.subjects.append(subject(60, "Jov", 1, False))

network.run()
