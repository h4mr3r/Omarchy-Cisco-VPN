import QtQuick
import Quickshell.Io
import qs.Commons
import qs.Ui

Panel {
  id: root
  moduleName: "h4mr3r.cisco-vpn"

  property string server: ""
  property string username: ""
  property bool serverDirty: false
  property bool usernameDirty: false
  property string errorText: ""
  property bool connected: false
  property bool busy: false
  property bool cancelRequested: false
  property string action: ""
  property string request: ""
  property string proxyMode: "off"
  property string proxyUrl: ""
  property bool proxyDirty: false
  property bool proxyExpanded: false
  property bool proxyChecking: false
  property string proxyCheckText: ""
  property string proxyCheckRequest: ""
  // Corporate proxy (inside the tunnel), served to apps by proxy_forwarder.py.
  property string corporateProxy: ""
  property string proxyLogin: ""
  property bool useVpnPassword: true
  property bool appsProxy: false
  property bool settingsLoaded: false
  property string forwarderMode: "stopped"
  property string forwarderUpstream: ""
  property string forwarderError: ""
  property bool forwarderBusy: false
  property string forwarderQueued: ""
  property string pendingProxyPassword: ""
  property string settingsRequest: ""
  property string afterSettings: ""
  // Untrusted gateway certificate offered for pinning; the request (with the
  // password) is kept only while this prompt is shown so "Trust and connect"
  // can retry without retyping.
  property var certificatePrompt: null
  property string lastConnectRequest: ""
  property bool certificatePinned: false
  readonly property bool forwarderWanted: dependenciesReady && (appsProxy || connected)
  readonly property string forwarderHelper: Qt.resolvedUrl("proxy_forwarder.py").toString().replace(/^file:\/\//, "")
  property bool dependenciesKnown: false
  property var missingPackages: []
  readonly property string helper: Qt.resolvedUrl("backend.py").toString().replace(/^file:\/\//, "")
  readonly property string dependencyHelper: Qt.resolvedUrl("dependencies.py").toString().replace(/^file:\/\//, "")
  readonly property bool dependenciesReady: dependenciesKnown && missingPackages.length === 0

  implicitWidth: icon.implicitWidth
  implicitHeight: icon.implicitHeight

  function refresh() {
    if (busy || dependencyProcess.running) return
    if (!dependenciesKnown) {
      dependencyProcess.running = true
      return
    }
    if (!dependenciesReady || statusProcess.running) return
    statusProcess.running = true
  }

  function installDependencies() {
    if (busy || dependenciesReady || !dependenciesKnown) return
    busy = true
    action = "install"
    errorText = ""
    installProcess.running = true
  }

  function applyResult(text, exitCode, showError) {
    try {
      var data = JSON.parse(text)
      if (!data.ok || exitCode !== 0) {
        if (showError) errorText = data.error || "VPN operation failed"
        if (showError && data.certificate && data.certificate.fingerprint) certificatePrompt = data.certificate
        return
      }
      connected = data.connected === true
      certificatePinned = data.certificatePinned === true
      if (data.settings && (!opened || !settingsLoaded)) applySettings(data.settings)
      if (showError && data.connected === true) {
        serverDirty = false
        usernameDirty = false
        proxyDirty = false
        errorText = ""
      }
      if (!opened) {
        if (!serverDirty) server = data.server || ""
        if (!usernameDirty) username = data.username || ""
        if (!proxyDirty) {
          proxyUrl = data.proxy || ""
          proxyMode = proxyUrl !== "" ? "manual" : "off"
        }
      }
    } catch (error) {
      if (showError) errorText = "VPN helper returned an invalid response"
    }
  }

  function applySettings(settings) {
    corporateProxy = settings.corporateProxy || ""
    proxyLogin = settings.proxyLogin || ""
    useVpnPassword = settings.useVpnPassword !== false
    appsProxy = settings.appsProxy === true
    settingsLoaded = true
    syncForwarder()
  }

  function runSettings(action, payload) {
    if (settingsProcess.running) return
    settingsRequest = payload ? JSON.stringify(payload) : ""
    settingsProcess.command = ["python", helper, action]
    settingsProcess.running = true
  }

  function syncForwarder() {
    if (forwarderWanted && !forwarderProcess.running) {
      forwarderMode = "starting"
      forwarderProcess.running = true
    } else if (!forwarderWanted && forwarderProcess.running) {
      forwarderProcess.running = false
    }
  }

  function sendForwarder(command) {
    var line = JSON.stringify(command)
    if (forwarderProcess.running && forwarderMode !== "starting") forwarderProcess.write(line + "\n")
    else {
      forwarderQueued = line
      syncForwarder()
    }
  }

  function signInCorporateProxy(password) {
    var upstream = corporateProxyField.text.trim() || corporateProxy
    var login = proxyLoginField.text.trim() || proxyLogin || username
    if (!upstream || !login || !password) {
      forwarderError = "Enter the corporate proxy, login, and password"
      return
    }
    forwarderError = ""
    forwarderBusy = true
    corporateProxy = upstream
    proxyLogin = login
    runSettings("save-settings", { corporateProxy: upstream, proxyLogin: login, useVpnPassword: useVpnPassword })
    sendForwarder({ mode: "upstream", upstream: upstream, username: login, password: password })
    proxyPasswordField.text = ""
  }

  function signOutCorporateProxy() {
    sendForwarder({ mode: "direct" })
  }

  function handleForwarderLine(line) {
    var event
    try { event = JSON.parse(line) } catch (error) { return }
    if (event.event === "listening") {
      forwarderMode = "direct"
      if (forwarderQueued !== "") {
        forwarderProcess.write(forwarderQueued + "\n")
        forwarderQueued = ""
      }
    } else if (event.event === "mode") {
      forwarderBusy = false
      forwarderMode = event.mode === "upstream" ? "upstream" : "direct"
      forwarderUpstream = event.upstream || ""
      if (forwarderMode === "upstream") forwarderError = ""
    } else if (event.event === "error") {
      forwarderBusy = false
      forwarderError = String(event.error || "Corporate proxy helper failed")
    }
  }

  onConnectedChanged: {
    syncForwarder()
    if (connected) {
      if (pendingProxyPassword !== "" && corporateProxy !== "") signInCorporateProxy(pendingProxyPassword)
    } else if (forwarderMode === "upstream") {
      signOutCorporateProxy()
    }
    pendingProxyPassword = ""
  }

  onForwarderWantedChanged: syncForwarder()

  function connectVpn() {
    if (busy) return
    if (!serverField.text.trim() || !userField.text.trim() || !passwordField.text) {
      errorText = "Enter a server, username, and password"
      return
    }
    if (proxyMode === "manual" && !proxyField.text.trim()) {
      errorText = "Enter a proxy address or set Proxy to Off"
      return
    }
    startConnect(JSON.stringify({
      server: serverField.text.trim(),
      username: userField.text.trim(),
      password: passwordField.text,
      proxyMode: proxyMode,
      proxyUrl: proxyField.text.trim()
    }))
    passwordField.text = ""
  }

  function startConnect(payload) {
    request = payload
    lastConnectRequest = payload
    certificatePrompt = null
    busy = true
    cancelRequested = false
    action = "connect"
    errorText = ""
    var password = JSON.parse(payload).password
    pendingProxyPassword = (useVpnPassword && corporateProxy !== "") ? password : ""
    actionProcess.command = ["python", helper, "connect"]
    actionProcess.running = true
  }

  function trustCertificateAndConnect() {
    if (busy || !certificatePrompt || settingsProcess.running) return
    var server = JSON.parse(lastConnectRequest).server
    afterSettings = "connect"
    runSettings("trust-certificate", { server: server, fingerprint: certificatePrompt.fingerprint })
  }

  function dismissCertificate() {
    certificatePrompt = null
    lastConnectRequest = ""
    errorText = ""
  }

  function forgetCertificate() {
    if (busy) return
    runSettings("forget-certificate", { server: serverField.text.trim() })
    certificatePinned = false
  }

  function disconnectVpn() {
    if (busy) return
    busy = true
    action = "disconnect"
    errorText = ""
    actionProcess.command = ["python", helper, "disconnect"]
    actionProcess.running = true
  }

  function checkCorporateProxy() {
    if (busy || proxyChecking || !connected) return
    proxyChecking = true
    proxyCheckText = ""
    proxyCheckRequest = JSON.stringify({ proxy: corporateProxyField.text.trim() })
    proxyCheckProcess.running = true
  }

  function describeProxyCheck(check) {
    var where = check.proxy + (check.source === "manual" ? "" : " (found via " + check.source + ")")
    if (check.status === 200) return "Corporate proxy " + where + " needs no login"
    if (check.status !== 407) return "Corporate proxy " + where + " answered HTTP " + check.status
    var schemes = check.schemes || []
    var names = schemes.map(function(s) {
      var lower = s.toLowerCase()
      if (lower === "basic") return "Basic (email/username + password)"
      if (lower === "ntlm") return "NTLM (Windows domain login)"
      if (lower === "negotiate") return "Negotiate (Kerberos or NTLM)"
      return s
    })
    return "Corporate proxy " + where + " requires a login: " + (names.length ? names.join(", ") : "unknown method")
  }

  function cancelVpn() {
    if (!busy || action !== "connect" || cancelRequested) return
    cancelRequested = true
    request = ""
    if (actionProcess.processId) actionProcess.signal(15)
  }

  onOpenedChanged: if (opened) {
    dependenciesKnown = false
    refresh()
  } else {
    passwordField.text = ""
    proxyPasswordField.text = ""
    proxyCheckText = ""
    certificatePrompt = null
    lastConnectRequest = ""
  }

  Timer {
    // Poll quickly only while the popup is open.
    interval: root.opened ? 5000 : 30000
    repeat: true
    running: true
    triggeredOnStart: true
    onTriggered: root.refresh()
  }

  Process {
    id: dependencyProcess
    command: ["python", root.dependencyHelper]
    stdout: StdioCollector {
      id: dependencyOutput
      waitForEnd: true
    }
    onExited: function(code) {
      try {
        var result = JSON.parse(dependencyOutput.text)
        if (code !== 0 || result.ok !== true || !Array.isArray(result.missing))
          throw new Error("Invalid dependency check")
        root.missingPackages = result.missing
        root.dependenciesKnown = true
        if (root.dependenciesReady) {
          root.errorText = ""
          root.refresh()
          if (root.opened) Qt.callLater(function() { serverField.forceActiveFocus() })
        }
      } catch (error) {
        root.errorText = "Could not check installed packages; run omarchy pkg add networkmanager-openconnect python-gobject in a terminal"
      }
    }
  }

  Process {
    id: installProcess
    command: ["pkexec", "/usr/share/omarchy/bin/omarchy-pkg-add",
              "networkmanager-openconnect", "python-gobject"]
    onExited: function(code) {
      root.busy = false
      root.dependenciesKnown = false
      if (code !== 0)
        root.errorText = "Installation failed or was cancelled; try again or run omarchy pkg add networkmanager-openconnect python-gobject in a terminal"
      root.refresh()
    }
  }

  Process {
    id: statusProcess
    command: ["python", root.helper, "status"]
    stdout: StdioCollector {
      id: statusOutput
      waitForEnd: true
    }
    onExited: function(code) {
      if (code === 0) root.applyResult(statusOutput.text, code, false)
      else if (root.opened && root.errorText === "") root.errorText = "Could not read VPN status"
    }
  }

  Process {
    id: actionProcess
    stdinEnabled: true
    onStarted: {
      if (root.cancelRequested) {
        signal(15)
      } else {
        if (root.request !== "") write(root.request + "\n")
        root.request = ""
      }
    }
    stdout: StdioCollector {
      id: actionOutput
      waitForEnd: true
    }
    onExited: function(code) {
      root.busy = false
      if (root.cancelRequested) root.errorText = "Connection cancelled"
      else root.applyResult(actionOutput.text, code, true)
      root.cancelRequested = false
      if (!root.connected) root.pendingProxyPassword = ""
      // Keep the request only while a certificate decision is pending.
      if (!root.certificatePrompt) root.lastConnectRequest = ""
      root.refresh()
    }
  }

  Process {
    id: proxyCheckProcess
    command: ["python", root.helper, "proxy-check"]
    stdinEnabled: true
    onStarted: {
      write(root.proxyCheckRequest + "\n")
      root.proxyCheckRequest = ""
    }
    stdout: StdioCollector {
      id: proxyCheckOutput
      waitForEnd: true
    }
    onExited: function(code) {
      root.proxyChecking = false
      try {
        var data = JSON.parse(proxyCheckOutput.text)
        if (code !== 0 || !data.ok) root.proxyCheckText = data.error || "Corporate proxy check failed"
        else {
          root.proxyCheckText = root.describeProxyCheck(data.proxyCheck)
          if (corporateProxyField.text.trim() === "") corporateProxyField.text = data.proxyCheck.proxy
        }
      } catch (error) {
        root.proxyCheckText = "VPN helper returned an invalid response"
      }
    }
  }

  Process {
    id: forwarderProcess
    command: ["python", root.forwarderHelper]
    stdinEnabled: true
    stdout: SplitParser {
      onRead: function(line) { root.handleForwarderLine(line) }
    }
    onExited: function(code) {
      root.forwarderMode = "stopped"
      root.forwarderUpstream = ""
      root.forwarderBusy = false
      if (root.forwarderWanted) forwarderRestart.start()
    }
  }

  Timer {
    id: forwarderRestart
    interval: 3000
    onTriggered: root.syncForwarder()
  }

  Process {
    id: settingsProcess
    stdinEnabled: true
    onStarted: {
      if (root.settingsRequest !== "") write(root.settingsRequest + "\n")
      root.settingsRequest = ""
    }
    stdout: StdioCollector {
      id: settingsOutput
      waitForEnd: true
    }
    onExited: function(code) {
      var next = root.afterSettings
      root.afterSettings = ""
      try {
        var data = JSON.parse(settingsOutput.text)
        if (data.settings) root.applySettings(data.settings)
        if (code !== 0 || !data.ok) {
          if (next === "connect") root.errorText = data.error || "Could not save the trusted certificate"
          else root.forwarderError = data.error || "Could not save proxy settings"
        } else if (next === "connect" && root.lastConnectRequest !== "") {
          root.startConnect(root.lastConnectRequest)
        }
      } catch (error) {
        root.forwarderError = "VPN helper returned an invalid response"
      }
    }
  }

  BarIconButton {
    id: icon
    anchors.fill: parent
    bar: root.bar
    text: root.connected ? "󰌆" : "󰦝"
    tooltipText: root.connected ? "Cisco VPN connected" : "Cisco VPN disconnected"
    onPressed: root.toggle()
  }

  KeyboardPanel {
    anchorItem: icon
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: serverField
    contentWidth: fittedContentWidth(Style.space(330))
    contentHeight: fittedContentHeight(fields.implicitHeight)

    Column {
      id: fields
      width: parent.width
      spacing: Style.space(8)

      Text {
        text: root.busy ? (root.action === "connect" ? "Cisco VPN · Connecting…" : (root.action === "install" ? "Cisco VPN · Installing packages…" : "Cisco VPN · Disconnecting…")) : (root.connected ? "Cisco VPN · Connected" : "Cisco VPN · Disconnected")
        color: root.barForeground
        font.family: root.bar ? root.bar.fontFamily : Style.font.family
        font.pixelSize: Style.font.body
      }

      Text {
        visible: root.dependenciesReady
        width: parent.width
        wrapMode: Text.WordWrap
        text: "Connect updates NetworkManager profile “Omarchy Cisco VPN” (server and username)"
        color: root.barForeground
        opacity: 0.65
        font.family: root.bar ? root.bar.fontFamily : Style.font.family
        font.pixelSize: Style.font.bodySmall
      }

      Text {
        visible: !root.dependenciesReady && root.dependenciesKnown
        width: parent.width
        wrapMode: Text.WordWrap
        text: "This widget needs " + root.missingPackages.join(" and ") + ". Install the missing packages? Administrator authentication is required."
        textFormat: Text.PlainText
        color: root.barForeground
        font.family: root.bar ? root.bar.fontFamily : Style.font.family
        font.pixelSize: Style.font.body
      }

      TextField {
        id: serverField
        visible: root.dependenciesReady
        width: parent.width
        placeholderText: "Server (vpn.example.com)"
        text: root.server
        enabled: !root.busy && !root.connected
        onTextChanged: {
          if (root.opened) root.serverDirty = true
          root.server = text
        }
        onAccepted: userField.forceActiveFocus()
      }

      TextField {
        id: userField
        visible: root.dependenciesReady
        width: parent.width
        placeholderText: "Username"
        text: root.username
        enabled: !root.busy && !root.connected
        onTextChanged: {
          if (root.opened) root.usernameDirty = true
          root.username = text
        }
        onAccepted: passwordField.forceActiveFocus()
      }

      TextField {
        id: passwordField
        visible: root.dependenciesReady
        width: parent.width
        placeholderText: "Password"
        password: true
        enabled: !root.busy && !root.connected
        onAccepted: root.connectVpn()
      }

      Button {
        visible: root.dependenciesReady && !root.connected
        enabled: !root.busy
        text: "Proxy to VPN server: " + (root.proxyMode === "off" ? "Off" : (root.proxyMode === "env" ? "From environment" : "Manual")) + (root.proxyExpanded ? " ▴" : " ▾")
        foreground: root.barForeground
        fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
        fontSize: Style.font.bodySmall
        leftAlign: true
        onClicked: root.proxyExpanded = !root.proxyExpanded
      }

      ButtonGroup {
        visible: root.dependenciesReady && !root.connected && root.proxyExpanded
        enabled: !root.busy
        focusable: false
        options: [
          { value: "off", label: "Off" },
          { value: "manual", label: "Manual" },
          { value: "env", label: "From environment" }
        ]
        value: root.proxyMode
        foreground: root.barForeground
        fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
        fontSize: Style.font.bodySmall
        onChanged: function(value) {
          root.proxyMode = value
          root.proxyDirty = true
        }
      }

      TextField {
        id: proxyField
        visible: root.dependenciesReady && !root.connected && root.proxyExpanded && root.proxyMode === "manual"
        width: parent.width
        placeholderText: "Proxy (http://proxy.example.com:8080)"
        text: root.proxyUrl
        enabled: !root.busy
        onTextChanged: {
          if (root.opened) root.proxyDirty = true
          root.proxyUrl = text
        }
        onAccepted: root.connectVpn()
      }

      Text {
        visible: root.dependenciesReady && !root.connected && root.proxyExpanded
        width: parent.width
        wrapMode: Text.WordWrap
        text: "Only needed when your network can reach the VPN server only through a proxy. Proxy logins are not supported here."
        color: root.barForeground
        opacity: 0.65
        font.family: root.bar ? root.bar.fontFamily : Style.font.family
        font.pixelSize: Style.font.bodySmall
      }

      Text {
        visible: root.dependenciesReady && root.connected
        text: "Corporate proxy"
        color: root.barForeground
        font.family: root.bar ? root.bar.fontFamily : Style.font.family
        font.pixelSize: Style.font.body
      }

      TextField {
        id: corporateProxyField
        visible: root.dependenciesReady && root.connected
        width: parent.width
        placeholderText: "Proxy host:port, e.g. proxy.corp.local:80 (blank = auto-detect)"
        text: root.corporateProxy
        enabled: !root.busy && !root.proxyChecking && root.forwarderMode !== "upstream"
        onAccepted: proxyLoginField.forceActiveFocus()
      }

      Button {
        visible: root.dependenciesReady && root.connected && root.forwarderMode !== "upstream"
        enabled: !root.busy && !root.proxyChecking
        text: root.proxyChecking ? "Checking corporate proxy…" : "Check corporate proxy"
        foreground: root.barForeground
        fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
        fontSize: Style.font.bodySmall
        bordered: true
        onClicked: root.checkCorporateProxy()
      }

      Text {
        visible: root.connected && root.proxyCheckText !== ""
        width: parent.width
        wrapMode: Text.WordWrap
        textFormat: Text.PlainText
        text: root.proxyCheckText
        color: root.barForeground
        font.family: root.bar ? root.bar.fontFamily : Style.font.family
        font.pixelSize: Style.font.bodySmall
      }

      TextField {
        id: proxyLoginField
        visible: root.dependenciesReady && root.connected && root.forwarderMode !== "upstream"
        width: parent.width
        placeholderText: "Proxy login (email)"
        text: root.proxyLogin || root.username
        enabled: !root.busy && !root.forwarderBusy
        onAccepted: proxyPasswordField.forceActiveFocus()
      }

      TextField {
        id: proxyPasswordField
        visible: root.dependenciesReady && root.connected && root.forwarderMode !== "upstream"
        width: parent.width
        placeholderText: "Proxy password"
        password: true
        enabled: !root.busy && !root.forwarderBusy
        onAccepted: root.signInCorporateProxy(text)
      }

      Button {
        visible: root.dependenciesReady && root.connected
        enabled: !root.busy && !root.forwarderBusy
        text: root.forwarderBusy ? "Signing in…"
              : (root.forwarderMode === "upstream" ? "Signed in to " + root.forwarderUpstream + " · Sign out"
                                                   : "Sign in to corporate proxy")
        foreground: root.barForeground
        fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
        fontSize: Style.font.bodySmall
        bordered: true
        onClicked: root.forwarderMode === "upstream" ? root.signOutCorporateProxy()
                                                     : root.signInCorporateProxy(proxyPasswordField.text)
      }

      Toggle {
        visible: root.dependenciesReady && root.connected
        width: parent.width
        label: "Sign in with the VPN password"
        description: "Signs in to the corporate proxy automatically on the next connect"
        checked: root.useVpnPassword
        foreground: root.barForeground
        fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
        titleSize: Style.font.bodySmall
        onClicked: {
          root.useVpnPassword = !root.useVpnPassword
          root.runSettings("save-settings", { useVpnPassword: root.useVpnPassword })
        }
      }

      Toggle {
        visible: root.dependenciesReady && (root.connected || root.appsProxy)
        width: parent.width
        label: "Use the corporate proxy in apps"
        description: "Sets http_proxy/https_proxy to 127.0.0.1:3128 (no password) for apps started from now on. Direct when the VPN is off."
        checked: root.appsProxy
        foreground: root.barForeground
        fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
        titleSize: Style.font.bodySmall
        onClicked: root.runSettings(root.appsProxy ? "apps-proxy-off" : "apps-proxy-on", null)
      }

      Text {
        visible: root.dependenciesReady && root.forwarderError !== ""
        width: parent.width
        wrapMode: Text.WordWrap
        textFormat: Text.PlainText
        text: root.forwarderError
        color: root.bar ? root.bar.urgent : Color.urgent
        font.family: root.bar ? root.bar.fontFamily : Style.font.family
        font.pixelSize: Style.font.bodySmall
      }

      Text {
        visible: root.errorText !== ""
        width: parent.width
        wrapMode: Text.WordWrap
        textFormat: Text.PlainText
        text: root.errorText
        color: root.bar ? root.bar.urgent : Color.urgent
        font.family: root.bar ? root.bar.fontFamily : Style.font.family
        font.pixelSize: Style.font.bodySmall
      }

      Text {
        visible: root.certificatePrompt !== null
        width: parent.width
        wrapMode: Text.WordWrap
        textFormat: Text.PlainText
        text: "Only trust this certificate if your IT team confirms the fingerprint, or you are sure this is the right server. It will be trusted for "
              + (root.certificatePrompt ? root.certificatePrompt.host : "") + " only."
        color: root.barForeground
        opacity: 0.8
        font.family: root.bar ? root.bar.fontFamily : Style.font.family
        font.pixelSize: Style.font.bodySmall
      }

      TextEdit {
        // Selectable so the fingerprint can be copied and compared with IT.
        visible: root.certificatePrompt !== null
        width: parent.width
        readOnly: true
        selectByMouse: true
        wrapMode: TextEdit.WrapAnywhere
        textFormat: TextEdit.PlainText
        text: root.certificatePrompt ? root.certificatePrompt.fingerprint : ""
        color: root.barForeground
        font.family: "monospace"
        font.pixelSize: Style.font.bodySmall
      }

      Row {
        visible: root.certificatePrompt !== null
        spacing: Style.space(8)

        Button {
          enabled: !root.busy && !settingsProcess.running
          text: root.certificatePrompt && root.certificatePrompt.changed
                ? "Trust the NEW certificate and connect" : "Trust this certificate and connect"
          foreground: root.barForeground
          fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
          fontSize: Style.font.bodySmall
          bordered: true
          onClicked: root.trustCertificateAndConnect()
        }

        Button {
          enabled: !root.busy
          text: "Don't trust"
          foreground: root.barForeground
          fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
          fontSize: Style.font.bodySmall
          onClicked: root.dismissCertificate()
        }
      }

      Button {
        visible: root.dependenciesReady && root.certificatePinned && !root.connected && root.certificatePrompt === null
        enabled: !root.busy && !settingsProcess.running
        text: "Using a trusted certificate for this server · Forget"
        foreground: root.barForeground
        fontFamily: root.bar ? root.bar.fontFamily : Style.font.family
        fontSize: Style.font.bodySmall
        leftAlign: true
        onClicked: root.forgetCertificate()
      }

      Rectangle {
        visible: root.dependenciesKnown
        width: parent.width
        height: Style.space(36)
        radius: Style.cornerRadius
        color: root.bar ? root.bar.foreground : Color.foreground
        opacity: root.busy ? 0.5 : 1

        Text {
          anchors.centerIn: parent
          text: root.busy ? (root.action === "connect" ? (root.cancelRequested ? "Cancelling…" : "Cancel") : "Working…") : (!root.dependenciesReady ? "Install packages" : (root.connected ? "Disconnect" : "Connect"))
          color: Color.background
          font.family: root.bar ? root.bar.fontFamily : Style.font.family
        }
        MouseArea {
          anchors.fill: parent
          enabled: (!root.busy && root.dependenciesKnown) || (root.action === "connect" && !root.cancelRequested)
          cursorShape: Qt.PointingHandCursor
          onClicked: root.busy ? root.cancelVpn() : (!root.dependenciesReady ? root.installDependencies() : (root.connected ? root.disconnectVpn() : root.connectVpn()))
        }
      }
    }
  }
}
