package pgparser

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

type protoKind bool

const (
	SimpleProto   protoKind = false
	ExtendedProto protoKind = true

	TagQuery    = byte('Q')
	TagParse    = byte('P')
	TagBind     = byte('B')
	TagDescribe = byte('D')
)

func IsQueryStart(startSymbol byte) bool {
	return (startSymbol == TagQuery) || (startSymbol == TagParse)
}

type PGQuery struct {
	Text   string
	Kind   protoKind
	Params string
}

func (q *PGQuery) ParsePacket(rawPacket []byte) error {
	var (
		tag byte
		err error
		len int32
	)

	buf := bytes.NewBuffer(rawPacket)
	for {
		tag, err = buf.ReadByte()
		if err != nil {
			break
		}
		err = binary.Read(buf, binary.BigEndian, &len)
		if err != nil {
			break
		}
		data := make([]byte, len-4)
		_, err = buf.Read(data)
		if err != nil {
			break
		}

		switch tag {
		case TagQuery:
			q.Kind = SimpleProto
			q.Text = string(data)
		case TagParse:
			q.Kind = ExtendedProto
			q.Text = string(data)
		case TagDescribe:
			fmt.Println("describe (str):", string(data))
			fmt.Println("describe (byte) :", data)
			_ = 0
		case TagBind:
			fmt.Println("params (str):", string(data))
			fmt.Println("params (byte) :", data)
			fmt.Println("len:", len)
			fmt.Println("tag:", tag)
			_ = 0
		}

		//fmt.Println("tag:", tag)
		//fmt.Println("len:", len)
		//fmt.Println("data:", string(data))
		//fmt.Println("data:", data)
	}

	if err != io.EOF {
		return err
	}
	return nil
}
