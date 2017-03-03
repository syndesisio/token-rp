//    Copyright 2017 Red Hat, Inc.
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package main

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
)

type urlFlag url.URL

var _ flag.Value = &urlFlag{}

func (uf *urlFlag) String() string {
	return fmt.Sprintf("%v", (*url.URL)(uf))
}

func (uf *urlFlag) Set(val string) error {
	if val == "" {
		return errors.New("url is empty")
	}

	ur, err := url.Parse(val)
	if err != nil {
		return err
	}

	if ur.Scheme == "" {
		return errors.New("url scheme is empty")
	}

	if ur.Host == "" {
		return errors.New("url host is empty")
	}

	*uf = *(*urlFlag)(ur)

	return nil
}
