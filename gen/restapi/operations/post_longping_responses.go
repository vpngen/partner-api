// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/vpngen/partner-api/gen/models"
)

// PostLongpingOKCode is the HTTP code returned for type PostLongpingOK
const PostLongpingOKCode int = 200

/*
PostLongpingOK Longping

swagger:response postLongpingOK
*/
type PostLongpingOK struct {

	/*
	  In: Body
	*/
	Payload *PostLongpingOKBody `json:"body,omitempty"`
}

// NewPostLongpingOK creates PostLongpingOK with default headers values
func NewPostLongpingOK() *PostLongpingOK {

	return &PostLongpingOK{}
}

// WithPayload adds the payload to the post longping o k response
func (o *PostLongpingOK) WithPayload(payload *PostLongpingOKBody) *PostLongpingOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the post longping o k response
func (o *PostLongpingOK) SetPayload(payload *PostLongpingOKBody) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PostLongpingOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

/*
PostLongpingDefault error

swagger:response postLongpingDefault
*/
type PostLongpingDefault struct {
	_statusCode int

	/*
	  In: Body
	*/
	Payload *models.Error `json:"body,omitempty"`
}

// NewPostLongpingDefault creates PostLongpingDefault with default headers values
func NewPostLongpingDefault(code int) *PostLongpingDefault {
	if code <= 0 {
		code = 500
	}

	return &PostLongpingDefault{
		_statusCode: code,
	}
}

// WithStatusCode adds the status to the post longping default response
func (o *PostLongpingDefault) WithStatusCode(code int) *PostLongpingDefault {
	o._statusCode = code
	return o
}

// SetStatusCode sets the status to the post longping default response
func (o *PostLongpingDefault) SetStatusCode(code int) {
	o._statusCode = code
}

// WithPayload adds the payload to the post longping default response
func (o *PostLongpingDefault) WithPayload(payload *models.Error) *PostLongpingDefault {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the post longping default response
func (o *PostLongpingDefault) SetPayload(payload *models.Error) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PostLongpingDefault) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(o._statusCode)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
