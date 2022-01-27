package repl

import (
	"strconv"

	"github.com/GridPlus/phonon-client/orchestrator"
	"github.com/GridPlus/phonon-client/session"
	"github.com/abiosoft/ishell/v2"
)

func cardPairLocal(c *ishell.Context) {
	if ready := checkActiveCard(c); !ready {
		return
	}
	c.Println("starting local card pairing")
	sessions := t.ListSessions()
	var otherCards []*session.Session
	var otherCardNames []string
	for _, session := range sessions {
		if session != activeCard {
			otherCards = append(otherCards, session)
			otherCardNames = append(otherCardNames, session.GetName())
		}
	}
	if len(otherCards) == 0 {
		c.Println("no available cards for pairing found")
		return
	}
	selection := c.MultiChoice(otherCardNames, "please select another card to pair with")
	if selection == -1 {
		c.Println("no card selected. exiting pairing...")
		return
	}

	pairingCard := otherCards[selection]
	c.Println("starting pairing with ", pairingCard.GetName())
	remoteCard := orchestrator.NewLocalCounterParty(pairingCard)
	activeCard.RemoteCard = remoteCard
	err := activeCard.RemoteCard.ConnectToCard(pairingCard.GetName())
	if err != nil {
		c.Err(err)
	}
	c.Println("cards successfully paired")
}

func sendPhonons(c *ishell.Context) {
	if ready := checkActiveCard(c); !ready {
		return
	}
	if paired := checkCardPaired(c); !paired {
		return
	}
	var keyIndices []uint16
	for _, i := range c.Args {
		keyIndex, err := strconv.ParseUint(i, 10, 16)
		if err != nil {
			c.Println("error parsing arg: ", i)
			c.Println("aborting send operation...")
			return
		}
		keyIndices = append(keyIndices, uint16(keyIndex))
	}

	err := activeCard.SendPhonons(keyIndices)
	if err != nil {
		c.Println("error during phonon send: ", err)
		return
	}
}
