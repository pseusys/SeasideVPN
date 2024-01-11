package main

import (
	"main/utils"
	"net/http"

	"github.com/sirupsen/logrus"
)

func WriteAndLogError(w http.ResponseWriter, code int, message string, err error) {
	w.Header().Add("Content-Type", "text/plain")
	w.WriteHeader(code)
	if err != nil {
		logrus.Errorln(message, err)
		w.Write([]byte(utils.JoinError(message, err).Error()))
	} else {
		logrus.Errorln(message)
		w.Write([]byte(message))
	}
}

func WriteRawData(w http.ResponseWriter, code int, data []byte) {
	w.Header().Add("Content-Type", "application/octet-stream")
	w.WriteHeader(code)
	w.Write(data)
}
