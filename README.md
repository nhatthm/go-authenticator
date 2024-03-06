# Authenticator

[![GitHub Releases](https://img.shields.io/github/v/release/nhatthm/go-authenticator)](https://github.com/nhatthm/go-authenticator/releases/latest)
[![Build Status](https://github.com/nhatthm/go-authenticator/actions/workflows/test.yaml/badge.svg)](https://github.com/nhatthm/go-authenticator/actions/workflows/test.yaml)
[![codecov](https://codecov.io/gh/nhatthm/go-authenticator/branch/master/graph/badge.svg?token=eTdAgDE2vR)](https://codecov.io/gh/nhatthm/go-authenticator)
[![Go Report Card](https://goreportcard.com/badge/go.nhat.io/authenticator)](https://goreportcard.com/report/go.nhat.io/authenticator)
[![GoDevDoc](https://img.shields.io/badge/dev-doc-00ADD8?logo=go)](https://pkg.go.dev/go.nhat.io/authenticator)
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/donate/?hosted_button_id=PJZSGJN57TDJY)

Manage and generate one-time passwords for multiple accounts.

## Prerequisites

- `Go >= 1.22`

### Keyring

Support **OS X**, **Linux/BSD (dbus)** and **Windows**.

#### OS X

The OS X implementation depends on the `/usr/bin/security` binary for
interfacing with the OS X keychain. It should be available by default.

#### Linux and *BSD

The Linux and *BSD implementation depends on the [Secret Service][SecretService] dbus
interface, which is provided by [GNOME Keyring](https://wiki.gnome.org/Projects/GnomeKeyring).

It's expected that the default collection `login` exists in the keyring, because
it's the default in most distros. If it doesn't exist, you can create it through the
keyring frontend program [Seahorse](https://wiki.gnome.org/Apps/Seahorse):

* Open `seahorse`
* Go to **File > New > Password Keyring**
* Click **Continue**
* When asked for a name, use: **login**

## Install

```bash
go get go.nhat.io/authenticator
```

## Data Storage and Security

The accounts are grouped as namespace, the list of namespaces is stored in `$HOME/.authenticator.toml`. The content is in plain text and in `toml` format.

For example

```toml
namespace = ["namespace1", "namespace2"]
```

The namespace data, such as namespace name, and accounts are stored in the keyring in `go.nhat.io/authenticator` service.

The totp secret of each account is stored in the keyring in `go.nhat.io/otp` service and `<namespace>/<account>` key.

## Donation

If this project help you reduce time to develop, you can give me a cup of coffee :)

### Paypal donation

[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/donate/?hosted_button_id=PJZSGJN57TDJY)

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;or scan this

<img src="https://user-images.githubusercontent.com/1154587/113494222-ad8cb200-94e6-11eb-9ef3-eb883ada222a.png" width="147px" />
