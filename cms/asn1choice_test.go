package cms

import (
	"encoding/asn1"
	"fmt"
	"testing"
)

// This type represents the contents of the ANS1 CHOICE
type ChoiceData struct {
	Option1 int    `asn1:"optional"`
	Option2 string `asn1:"tag:1,optional"`
	Option3 []byte `asn1:"tag:2,optional"`
}

func TestName(t *testing.T) {
	// Create a variable of type ChoiceData with the data to be serialized
	// Set the value of the chosen option (Option2)
	choiceData2 := ChoiceData{
		Option2: "Test",
	}

	// Use the Marshal function from the asn1 package to serialize the data
	data, err := asn1.Marshal(choiceData2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Serialized:\n%v\n", data)

	// This is an example of an ANS1 CHOICE encoded as a byte slice
	// The chosen option is Option2, which has tag 1
	//data := []byte{0xA1, 0x05, 0x54, 0x65, 0x73, 0x74}

	// Create a variable of type ChoiceData to hold the decoded data
	var choiceData ChoiceData

	// Use the Unmarshal function from the asn1 package to parse the data
	_, err = asn1.Unmarshal(data, &choiceData)
	if err != nil {
		t.Fatal(err)
	}

	// The parsed data is now stored in the choiceData variable
	fmt.Println("Option1:", choiceData.Option1)
	fmt.Println("Option2:", choiceData.Option2)
	fmt.Println("Option3:", choiceData.Option3)

}
