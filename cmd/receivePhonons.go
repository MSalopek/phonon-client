/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"

	"github.com/GridPlus/phonon-client/card"
	"github.com/spf13/cobra"
)

// receivePhononsCmd represents the receivePhonons command
var receivePhononsCmd = &cobra.Command{
	Use:   "receivePhonons",
	Short: "Test command to send sample phonons and receive them",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		receivePhonons()
	},
}

func init() {
	rootCmd.AddCommand(receivePhononsCmd)
}

func receivePhonons() {
	cs, err := card.Connect(readerIndex)
	if err != nil {
		return
	}
	cs.Select()

	//Have the card SendPhonons and receive them back for testing
	testKeyIndices := []uint16{1, 2, 3, 4, 5, 6, 7, 8}
	transferPackets, err := cs.SendPhonons(testKeyIndices, false)
	if err != nil {
		fmt.Print("error in SEND_PHONONS command: ", err)
	} else {
		fmt.Printf("received SEND_PHONONS transfer packet: % X\n", transferPackets)
	}
	err = cs.ReceivePhonons(transferPackets)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("received phonon packets")
	// for i, packet := range transferPackets {
	// 	err = cs.ReceivePhonons(transferPackets)
	// 	if err != nil {
	// 		fmt.Println("error receiving phonons: ", err)
	// 	} else {
	// 		fmt.Printf("card received phonon packet number %v\n", i)
	// 	}
	// }
}
