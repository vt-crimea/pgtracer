package pgparser

import (
	"bytes"
	"container/list"
	"encoding/binary"
	"fmt"
	"pgtracer/database"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
)

type protoKind bool
type messageDirection bool

const (
	SimpleProto   protoKind = false
	ExtendedProto protoKind = true

	DirectionIn  messageDirection = true
	DirectionOut messageDirection = false

	TagQuery    = byte('Q')
	TagParse    = byte('P')
	TagBind     = byte('B')
	TagDescribe = byte('D')

	TagReadyForQuery            = byte('Z')
	TagCommandComplete          = byte('C')
	TagCommandCompletePartially = byte('s')
	TagError                    = byte('E')
)

func IsReadyForQuery(data [6]byte) bool {
	return data == [6]byte{90, 0, 0, 0, 5, 73} || data == [6]byte{90, 0, 0, 0, 5, 84} || data == [6]byte{90, 0, 0, 0, 5, 69}
}

func IsQueryStart(startSymbol byte) bool {
	return (startSymbol == TagQuery) || (startSymbol == TagParse)
}

func IsSync(endBytes []byte) bool {
	return true
}

type Message struct {
	Tag         byte
	Contents    []byte
	BytesToRead int
	Direction   messageDirection
}

type MessageQueue struct {
	Id int

	Ip   string
	Port string

	ProtoKind protoKind

	Query  string
	Params []string
	Error  string
	Result string

	TimeStart  time.Time
	TimeFinish time.Time

	Messages list.List
}

func (q *MessageQueue) ParseParams(rawParams []byte) (err error) {
	var numParams int32
	var paramLen int32

	buf := bytes.NewBuffer(rawParams)

	// 2 нуля пропускаем (по идее тэг дальнейших данных)
	data := make([]byte, 2)
	_, err = buf.Read(data)
	if err != nil {
		return
	}
	//если там не нули, значит наверно это не параметры (?)
	if data[0] != 0 || data[1] != 0 {
		return
	}

	//кол-во параметров
	err = binary.Read(buf, binary.BigEndian, &numParams)
	if err != nil {
		return
	}
	if numParams == 0 {
		return
	}
	//создаем массив параметров в нашей структуре
	q.Params = make([]string, numParams)

	//находим значения параметров
	for i := 0; i < int(numParams); i++ {
		//длина параметра
		err = binary.Read(buf, binary.BigEndian, &paramLen)
		if err != nil {
			return
		}
		//значение параметра
		data = make([]byte, paramLen)
		_, err = buf.Read(data)
		if err != nil {
			return
		}
		//сохраняем
		q.Params[i] = string(data)
	}

	return
}

func (q *MessageQueue) ParseContents(tag byte, contents []byte, direction messageDirection) (err error) {
	switch tag {
	case TagQuery, TagParse:
		q.Query = string(contents)
		q.TimeStart = time.Now()

		if err = q.SaveQuery(database.DB); err != nil {
			fmt.Println("eror saving query: ", err)
		}
	case TagBind:
		err = q.ParseParams(contents)
		if err != nil {
			fmt.Println(err)
		}

		q.SaveQueryParams(database.DB)
	case TagCommandComplete, TagCommandCompletePartially:
		q.Result = string(contents)
		q.TimeFinish = time.Now()

		fmt.Println("From:", q.Ip+":"+q.Port+"-------------------------------------------")
		fmt.Println("Query:", q.Query)
		fmt.Println("Params:", q.Params)
		fmt.Println("Result:", q.Result)
		fmt.Println("Duration:", q.TimeFinish.Sub(q.TimeStart).Milliseconds())

		if err = q.UpdateQuery(database.DB); err != nil {
			fmt.Println("eror saving query: ", err)
		}
	case TagError:
		if direction == DirectionOut {
			q.Error = string(contents)
			q.TimeFinish = time.Now()
			fmt.Println("From:", q.Ip+":"+q.Port+"-------------------------------------------")
			fmt.Println("Query:", q.Query)
			fmt.Println("Params:", q.Params)
			fmt.Println("Error:", q.Error)
			fmt.Println("Duration:", q.TimeFinish.Sub(q.TimeStart).Milliseconds())

			if err = q.UpdateQuery(database.DB); err != nil {
				fmt.Println("eror saving query: ", err)
			}
		}
	}

	return nil
}

func (q *MessageQueue) ParseMessages(packageData []byte) (err error) {
	var msg *Message = &Message{}

	//fmt.Println(q.Messages.Len())

	pos := 0
	dataLen := len(packageData)
	tailLen := 0
	bytesToRead := 0

	//крайнее собщение
	if q.Messages.Len() > 0 {
		msg = q.Messages.Back().Value.(*Message)
		bytesToRead = msg.BytesToRead
	}
	for {

		if bytesToRead == 0 {
			if pos >= dataLen {
				break
			}
			if dataLen < 5 {
				return
			}
			//новое пустое сообщение
			msg = &Message{}
			q.Messages.PushBack(msg)

			msg.Direction = DirectionIn
			msg.Tag = packageData[pos]
			bytesToRead = int(binary.BigEndian.Uint32(packageData[pos+1:pos+5]) - 4)
			msg.BytesToRead = bytesToRead
			pos += 5

			continue
		} else {
			tailLen = dataLen - pos
			if bytesToRead <= tailLen {
				msg.Contents = append(msg.Contents, packageData[pos:pos+msg.BytesToRead]...)
				pos += bytesToRead

				bytesToRead = 0
				msg.BytesToRead = 0

				q.ParseContents(msg.Tag, msg.Contents, DirectionIn)
			} else {
				msg.Contents = append(msg.Contents, packageData[pos:dataLen]...)
				msg.BytesToRead -= tailLen
				break
			}

		}

	}
	return nil
}

func (q *MessageQueue) ParseAnswerMessages(packageData []byte) (err error) {
	var (
		tail        [6]byte
		bytesToRead int
	)
	len := len(packageData)

	if len < 5 {
		return
	}

	//error tag
	if packageData[0] == TagError {
		bytesToRead = int(binary.BigEndian.Uint32(packageData[1:5]) - 4)
		if bytesToRead > len-5 {
			return
		}
		contents := packageData[5 : 5+bytesToRead]

		msg := &Message{Tag: TagError, Contents: contents, Direction: DirectionOut}
		q.Messages.PushBack(msg)
		q.ParseContents(TagError, contents, DirectionOut)

		return
	}

	//ready for query and command complete
	copy(tail[:], packageData[len-6:len])
	if IsReadyForQuery(tail) {
		//fmt.Println("Ready For Query")

		for i := len - 7; i > 0; i-- {
			b := packageData[i]
			switch b {
			case TagCommandComplete, TagCommandCompletePartially:

				bytesToRead = int(binary.BigEndian.Uint32(packageData[i+1:i+5]) - 4)

				if bytesToRead == len-i-11 {
					//fmt.Println("ok")
					contents := packageData[i+5 : i+5+bytesToRead]
					//fmt.Println("command complete:", string(contents))
					msg := &Message{Tag: b, Contents: contents, Direction: DirectionOut}
					q.Messages.PushBack(msg)
					q.ParseContents(b, contents, DirectionOut)
					return nil
				}
			}

		}
	}
	return nil
}

func (q *MessageQueue) SaveQuery(db *sqlx.DB) (err error) {
	if db == nil {
		return
	}
	toReplace := []byte{0}

	if q.Id == 0 {
		sqlStr := `Insert into pgparser.queries (ip, port, querytext, timestart)
				values ($1, $2, $3, $4) returning id`
		query := strings.Replace(q.Query, string(toReplace), "", -1)
		err = db.Get(&(q.Id), sqlStr, q.Ip, q.Port, query, q.TimeStart)
		//_, err = db.Exec(sqlStr, q.Ip, q.Port, q.Query, q.Params, q.Result, q.TimeStart, q.TimeFinish)

	}
	return
}

func (q *MessageQueue) UpdateQuery(db *sqlx.DB) (err error) {
	if db == nil {
		return
	}
	toReplace := []byte{0}

	if q.Id != 0 {
		resText := strings.Replace(q.Result, string(toReplace), "", -1)
		errText := strings.Replace(q.Error, string(toReplace), "", -1)
		sqlStr := `update pgparser.queries set queryresult=$1,  
					timefinish=$2, errortext=$3
					where id=$4`
		_, err = db.Exec(sqlStr, resText, q.TimeFinish, errText, q.Id)
	}
	return
}

func (q *MessageQueue) SaveQueryParams(db *sqlx.DB) (err error) {
	if db == nil {
		return
	}
	toReplace := []byte{0}

	if q.Id != 0 {
		sqlStr := `insert into pgparser.params (queryid, value) values ($1, $2) `
		for _, p := range q.Params {
			p := strings.Replace(p, string(toReplace), "", -1)
			_, err = db.Exec(sqlStr, q.Id, p)
		}
	}
	return
}

/*
func (q *PGQuery) ParseParams(rawParams []byte) (err error) {
	var numParams int32
	var paramLen int32

	buf := bytes.NewBuffer(rawParams)

	// 2 нуля пропускаем (по идее тэг дальнейших данных)
	data := make([]byte, 2)
	_, err = buf.Read(data)
	if err != nil {
		return
	}
	//если там не нули, значит наверно это не параметры (?)
	if data[0] != 0 || data[1] != 0 {
		return
	}

	//кол-во параметров
	err = binary.Read(buf, binary.BigEndian, &numParams)
	if err != nil {
		return
	}
	if numParams == 0 {
		return
	}
	//создаем массив параметров в нашей структуре
	q.Params = make([]string, numParams)

	//находим значения параметров
	for i := 0; i < int(numParams); i++ {
		//длина параметра
		err = binary.Read(buf, binary.BigEndian, &paramLen)
		if err != nil {
			return
		}
		//значение параметра
		data = make([]byte, paramLen)
		_, err = buf.Read(data)
		if err != nil {
			return
		}
		//сохраняем
		q.Params[i] = string(data)
	}

	return
}
*/
