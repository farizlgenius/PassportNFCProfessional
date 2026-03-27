# PassportNFCProfessional.framework

A Swift-based framework for reading electronic passport (ePassport) data via NFC using a Smart Card Reader and Apple’s CryptoTokenKit.


## 📦 Release Notes
### v1.1.0
- Added logging
- Added export log feature

### v1.0.0
- Initial release


## ⚙️ Requirements
- Xcode 16+
- iOS device with NFC
- Supported Smart Card Reader


## 📥 Installation
1. Create group `Libs`
2. Add `PassportNFCProfessional.framework`
3. Set to **Embed & Sign**


# UIKit Integration

## Setup

```swift
var readerController: ReaderController!
var passportController: PassportController!
```

```swift
readerController = ReaderController()
let isConnected = readerController.initSmartCard()

passportController = PassportController(reader: readerController, isConnected: isConnected)
passportController.delegate = self
```

## Delegate

```swift
extension YourViewController: PassportControllerDelegate {

    func onBeginCardSession(isSuccess: Bool) {
        // Handle session start
    }

    func onProgressReadPassportData(progress: Float) {
        // Update progress UI
    }

    func onCompleteReadPassportData(data: PassportModel) {
        // Handle success
    }

    func onErrorOccur(errorMessage: String, isError: Bool) {
        // Handle error
    }
}
```

## Start Reading

```swift
passportController.ReadRFIDData(
    documentNo: "XXXXXXXX",
    dob: "YYMMdd",
    doe: "YYMMdd"
)
```

# SwiftUI Integration

## ViewModel

```swift
class PassportViewModel: NSObject, ObservableObject {

    @Published var isConnected = false
    @Published var progress: Float = 0
    @Published var passportData: PassportModel?
    @Published var errorMessage: String?

    private var readerController: ReaderController!
    private var passportController: PassportController!

    override init() {
        super.init()
        readerController = ReaderController()
        let connected = readerController.initSmartCard()

        passportController = PassportController(reader: readerController, isConnected: connected)
        passportController.delegate = self
    }

    func readPassport(documentNo: String, dob: String, doe: String) {
        passportController.ReadRFIDData(documentNo: documentNo, dob: dob, doe: doe)
    }
}
```

## Delegate Bridge

```swift
extension PassportViewModel: PassportControllerDelegate {

    func onBeginCardSession(isSuccess: Bool) {
        DispatchQueue.main.async { self.isConnected = isSuccess }
    }

    func onProgressReadPassportData(progress: Float) {
        DispatchQueue.main.async { self.progress = progress }
    }

    func onCompleteReadPassportData(data: PassportModel) {
        DispatchQueue.main.async { self.passportData = data }
    }

    func onErrorOccur(errorMessage: String, isError: Bool) {
        DispatchQueue.main.async { self.errorMessage = errorMessage }
    }
}
```

## SwiftUI View

```swift
struct PassportView: View {

    @StateObject private var vm = PassportViewModel()

    var body: some View {
        VStack {
            Button("Read Passport") {
                vm.readPassport(documentNo: "XXX", dob: "YYMMdd", doe: "YYMMdd")
            }

            ProgressView(value: vm.progress)

            if let data = vm.passportData {
                Text(data.holderFullName)
            }

            if let error = vm.errorMessage {
                Text(error)
            }
        }
    }
}
```


## Logging

```swift
Logger.shared.exportLogFile()
```

---

## Notes
- DOB/DOE format: YYMMdd
- NFC must be enabled
- Reader must be connected
