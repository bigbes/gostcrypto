package vko //nolint:testpackage // white-box: tests unexported leBytes2big/big2leFixed/reverse/curve helpers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"testing"

	"github.com/bigbes/gostcrypto/gost3410curves"
	"github.com/bigbes/gostcrypto/gostr341194"
	"github.com/bigbes/gostcrypto/streebog"
)

func streebogNew256() hash.Hash { return streebog.New256() }
func streebogNew512() hash.Hash { return streebog.New512() }
func gostr341194New() hash.Hash { return gostr341194.New() }

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}

	return b
}

// deriveQ derives the LE-encoded public point d·P on curve c, using the
// clean-room curve arithmetic. KAT #1 gives only the scalars.
func deriveQ(t *testing.T, c *gost3410curves.Curve, dLE []byte) []byte {
	t.Helper()

	d := leBytes2big(dLE)
	d.Mod(d, c.Q)

	q := c.ScalarMult(d, c.Base())
	if q.IsInfinity() {
		t.Fatalf("deriveQ: identity point")
	}

	size := c.PointSize()
	out := make([]byte, 0, 2*size)

	out = append(out, big2leFixed(q.X, size)...)
	out = append(out, big2leFixed(q.Y, size)...)

	return out
}

// TestKAT pins the exact hex vectors from the guide (KAT #1 / KAT #2).
func TestKAT(t *testing.T) {
	t.Parallel()

	c2001 := curve2001Test()
	if !c2001.IsOnCurve(c2001.Base()) {
		t.Fatal("2001 test curve base point is not on the curve")
	}

	cA := curve2012paramSetA()
	if !cA.IsOnCurve(cA.Base()) {
		t.Fatal("512 paramSetA base point is not on the curve")
	}

	// KAT #1 — VKO 2001, test paramset, cofactor 1 (guide lines 264-279).
	d1 := mustHex(t, "1df129e43dab345b68f6a852f4162dc69f36b2f84717d08755cc5c44150bf928")
	d2 := mustHex(t, "5b9356c6474f913f1e83885ea0edd5df1a43fd9d799d219093241157ac9ed473")
	ukm2001 := mustHex(t, "5172be25f852a233")
	Q1 := deriveQ(t, c2001, d1)
	Q2 := deriveQ(t, c2001, d2)
	kek2001 := "ee4618a0dbb10cb31777b4b86a53d9e7ef6cb3e400101410f0c0f2af46c494a6"

	// KAT #2 — VKO 2012, id-tc26-gost-3410-12-512-paramSetA (guide lines 281-308).
	dA := mustHex(t, "c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8"+
		"c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667")
	QA := mustHex(t, "aab0eda4abff21208d18799fb9a8556654ba783070eba10cb9abb253ec56dcf5"+
		"d3ccba6192e464e6e5bcb6dea137792f2431f6c897eb1b3c0cc14327b1adc0a7"+
		"914613a3074e363aedb204d38d3563971bd8758e878c9db11403721b48002d38"+
		"461f92472d40ea92f9958c0ffa4c93756401b97f89fdbe0b5e46e4a4631cdb5a")
	dB := mustHex(t, "48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b"+
		"8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db")
	QB := mustHex(t, "192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5e"+
		"fca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a651"+
		"04883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03b"+
		"b598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79")
	ukm2012 := mustHex(t, "1d80603c8544c727")
	kek256 := "c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221"
	kek512 := "79f002a96940ce7bde3259a52e015297adaad84597a0d205b50e3e1719f97bfa" +
		"7ee1d2661fa9979a5aa235b558a7e6d9f88f982dd63fc35a8ec0dd5e242d3bdf"

	type row struct {
		name      string
		fn        func(prv, pub, ukm []byte) ([]byte, error)
		prv, peer []byte
		ukm       []byte
		want      string
	}

	rows := []row{
		{"2001/A", VKO2001TestCurve, d1, Q2, ukm2001, kek2001},
		{"2001/B", VKO2001TestCurve, d2, Q1, ukm2001, kek2001},
		{"2012_256/A", VKO2012_256, dA, QB, ukm2012, kek256},
		{"2012_256/B", VKO2012_256, dB, QA, ukm2012, kek256},
		{"2012_512/A", VKO2012_512, dA, QB, ukm2012, kek512},
		{"2012_512/B", VKO2012_512, dB, QA, ukm2012, kek512},
	}

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			t.Parallel()

			got, err := r.fn(r.prv, r.peer, r.ukm)
			if err != nil {
				t.Fatalf("VKO: %v", err)
			}

			if want := mustHex(t, r.want); !bytes.Equal(got, want) {
				t.Fatalf("KEK mismatch:\n got = %x\n want= %x", got, want)
			}
		})
	}
}

// derTLV encodes one definite-length DER TLV.
func derTLV(tag byte, content []byte) []byte {
	n := len(content)

	var l []byte

	switch {
	case n < 0x80:
		l = []byte{byte(n)}
	case n < 0x100:
		l = []byte{0x81, byte(n)}
	default:
		l = []byte{0x82, byte(n >> 8), byte(n)}
	}

	return append(append([]byte{tag}, l...), content...)
}

// TestKAT_Engine04PkeyDerive ports the gost-engine 'derive' subtest
// (tmp/engine/test/04-pkey.t:160-358). Each fixture row carries two static
// PKCS#8 private keys (Alice, Bob) plus three expected SHA-256 values:
//
//   - aliceHash / bobHash — sha256 of the DER SubjectPublicKeyInfo produced by
//     `openssl pkey -pubout -outform DER` (04-pkey.t:326,332). The SPKI is
//     SEQUENCE{ AlgorithmIdentifier, BIT STRING{ 00, OCTET STRING LE(X)||LE(Y) } }
//     with the AlgorithmIdentifier byte-identical to the one in the private
//     key, so we rebuild it here from the alg hex + our DeriveQLE output.
//   - secretHash — sha256 of the raw shared key from `openssl pkeyutl -derive
//     ... -pkeyopt ukmhex:0100000000000000` (04-pkey.t:335,338). With an
//     8-byte UKM the engine takes the pre-2018 VKO path
//     (tmp/engine/gost_ec_keyx.c:227-242): 32-byte output, digest = the key
//     type's default digest, with GOST R 34.11-2012-512 downgraded to
//     34.11-2012-256 — so 2001 keys use KEK2001 (34.11-94) and ALL 2012 keys,
//     including 512-bit ones, use KEK2012256 (Streebog-256).
//
// The private-key OCTET STRING payload is the raw little-endian scalar
// (tmp/engine/gost_ameth.c:613-617 — "masked" form with zero masks →
// BN_lebin2bn); the hex below was mechanically extracted from the PEM
// fixtures. Curve mapping: XchA = CryptoPro-A and XchB = CryptoPro-C
// (RFC 4357 §11.4); the *-rangetest rows reuse the cofactor-4 curves
// (tc26 256-A, 512-C) with boundary scalars.
//
// The paramSetA-256 and paramSetC-512 rows also carry a "Malice" public key
// lying in the small subgroup; the engine refuses to derive against it
// (04-pkey.t:341-348, negative test) and so must we.
func TestKAT_Engine04PkeyDerive(t *testing.T) {
	t.Parallel()

	ukm := mustHex(t, "0100000000000000") // 04-pkey.t:335 ukmhex.
	curve := func(oid string) *gost3410curves.Curve {
		c, err := gost3410curves.CurveByOID(oid)
		if err != nil {
			t.Fatalf("CurveByOID(%s): %v", oid, err)
		}

		return c
	}

	type fix struct {
		name       string // engine fixture id (04-pkey.t derive %derives key).
		curve      *gost3410curves.Curve
		kek        func(c *gost3410curves.Curve, prvLE, pubLE, ukmRaw []byte) ([]byte, error)
		alg        string // AlgorithmIdentifier DER hex (shared by priv and SPKI).
		alicePrv   string // little-endian private scalar hex.
		aliceHash  string
		bobPrv     string
		bobHash    string
		secretHash string
		malicePub  string // optional small-subgroup LE public key hex.
	}

	fixtures := []fix{
		{ // 04-pkey.t:162-171.
			name:       "id-GostR3410-2001-TestParamSet",
			curve:      Curve2001Test(),
			kek:        KEK2001,
			alg:        "301c06062a8503020213301206072a85030202230006072a850302021e01",
			alicePrv:   "8390ea3f6653e6c31afbe9cc5e8898b454ced466c657ed9069621ae202c67913",
			aliceHash:  "e49ff6ce142a54da577de28c69140b8eaca21bbf97a3584b2a071b974ab62dd2",
			bobPrv:     "0d44a5a184f0f18ed1eaf1ea6e15f8560f6c149e7011fc15de1050abef7d5758",
			bobHash:    "13ff71a7787cf321d04e54fee29714008d81a1c972c871f374803ab96639d901",
			secretHash: "dc0e3c93b7c4e9186cf9d83ae23a8f080a7916e2d54a43e583e95795a486eaa6",
		},
		{ // 04-pkey.t:172-181.
			name:       "id-GostR3410-2001-CryptoPro-A-ParamSet",
			curve:      curve("1.2.643.2.2.35.1"),
			kek:        KEK2001,
			alg:        "301c06062a8503020213301206072a85030202230106072a850302021e01",
			alicePrv:   "004b0fe65f87302b0b79ec39a08690c6523eb30c6ec0136275aad6e743a6176e",
			aliceHash:  "8f3aad4a05ecf47377eff12293c993e353bc218cfb0f9af0c407bcf044454950",
			bobPrv:     "cbb64aa2bd70171a24d90748a054b7b8bcaebd89a9b1d54de0ba8ec8388abddc",
			bobHash:    "bcc1049e775dcaed60b00da185cd93dcc6fa705a14ed2add9f5af00d71e37f95",
			secretHash: "defbbd083692895d5c5c6a87e066b30964e5b527f56cf965a390096ba4bc9afb",
		},
		{ // 04-pkey.t:182-191.
			name:       "id-GostR3410-2001-CryptoPro-B-ParamSet",
			curve:      curve("1.2.643.2.2.35.2"),
			kek:        KEK2001,
			alg:        "301c06062a8503020213301206072a85030202230206072a850302021e01",
			alicePrv:   "14db6a99c7048643223a6f1868b020ff6a4782eb4631873e57daf30f06596277",
			aliceHash:  "c0306a860d36f0948dff7ae3b6b721a254f350f078a32062c5345365558e35e0",
			bobPrv:     "2ec3edc77794d0b4d10ff25cb46d3a1a4f981b3bd7fb7074dbc35571a765d30f",
			bobHash:    "f5cb24ceb3433fc580ffc8058336dc6254477fb24df178427423540db18dd1b5",
			secretHash: "521cc034b603c21e26a3e47e38b56880bdd986089d14d6ffce4fbcad2d0f20bb",
		},
		{ // 04-pkey.t:192-201.
			name:       "id-GostR3410-2001-CryptoPro-C-ParamSet",
			curve:      curve("1.2.643.2.2.35.3"),
			kek:        KEK2001,
			alg:        "301c06062a8503020213301206072a85030202230306072a850302021e01",
			alicePrv:   "3518d13a65b308efc78d8df6b9b3520977a309457824c9bae862c4fb06142511",
			aliceHash:  "e882207141dc1a714002907d610ae5a7ba79a9c0c84bef13491038181f37d0f2",
			bobPrv:     "67e0a6a5840afd4ea6e6772f8ab8660a661934b4f0dc0f5a0088a3ad4e6a5320",
			bobHash:    "7f11fe4075a198c3afca5b4364afdc1cd45325cfa999a5b84fd510f90c3527c3",
			secretHash: "d61f1f55a1ad012884b969dbe2550f38f2356a029e5d8af07d50d10ca9812c58",
		},
		{ // 04-pkey.t:202-211; XchA shares the CryptoPro-A curve (RFC 4357 §11.4).
			name:       "id-GostR3410-2001-CryptoPro-XchA-ParamSet",
			curve:      curve("1.2.643.2.2.35.1"),
			kek:        KEK2001,
			alg:        "301c06062a8503020213301206072a85030202240006072a850302021e01",
			alicePrv:   "9f73778adbf4c32abb81e700491df7e22bc143528d48dee258d0558e131d88c2",
			aliceHash:  "947ba3299cdb129386808638514bc4a21262123cd7e47ade7579e51439c70dac",
			bobPrv:     "6c31d7371476fb00c8eaf48c5f89475e433cdd21493bf2edff726c0e4eca228d",
			bobHash:    "2cb9078a00f955aaa398d10c021dae9e954573c5d9f4d3190c4bce887731ea11",
			secretHash: "f4fb7e0f533a59cc40f17131f620be821e528f9cec2915b9f813159dc0e3a29e",
		},
		{ // 04-pkey.t:212-221; XchB shares the CryptoPro-C curve (RFC 4357 §11.4).
			name:       "id-GostR3410-2001-CryptoPro-XchB-ParamSet",
			curve:      curve("1.2.643.2.2.35.3"),
			kek:        KEK2001,
			alg:        "301c06062a8503020213301206072a85030202240106072a850302021e01",
			alicePrv:   "8a92bf943f072d55b5393553ed7e03558c310db9436325e6190099895406ac62",
			aliceHash:  "44f89a85bbf256836f77e765f6ee0222d8ffd1f8f85e5197b06931178aa081ca",
			bobPrv:     "efa37d450533477658fc5017c818e0a72a089934dad71adda628bd98757a8c2d",
			bobHash:    "be866445486068067f0e479b83dde1b1b9a07fc8bc8fa5f5c60d15a39e3f3562",
			secretHash: "e8d30d98363b8b889464f4664c6a0403723484923e2db89039603c7ae294c504",
		},
		{ // 04-pkey.t:222-234; cofactor-4 curve, carries a Malice key.
			name:       "id-tc26-gost-3410-2012-256-paramSetA",
			curve:      curve("1.2.643.7.1.2.1.1.1"),
			kek:        KEK2012256,
			alg:        "301706082a85030701010101300b06092a8503070102010101",
			alicePrv:   "f9faed9e6d8c10f620d85879a27f85de1a08f63a28c9baae18b1b4cda07dfe07",
			aliceHash:  "a04b252bedc05f69fc92d8e985b52f0f984bccf3ef9f980ac7aca85f5ef11987",
			bobPrv:     "d5c1776fab5cdd0419b35631b558e05047f764c02cc5e8a48889591f4150ac2a",
			bobHash:    "c019d8939e12740a328625cea86efa3b39170412772b3c110536410bdd58a854",
			secretHash: "e9f7c57547fa0cd3c9942c62f9c74a553626d5f9810975a476825cd6f22a4e86",
			malicePub: "77592f8c11c5e7acc09d6af3d1805dbc5393c3955d5ab43875003505c6807f7f" +
				"cd0e8ea4344fb70642d93fda75821835fbb94ac1180f1daa5f019f0f52827e7e",
		},
		{ // 04-pkey.t:235-244.
			name:       "id-tc26-gost-3410-2012-256-paramSetB",
			curve:      curve("1.2.643.7.1.2.1.1.2"),
			kek:        KEK2012256,
			alg:        "301706082a85030701010101300b06092a8503070102010102",
			alicePrv:   "d0e86e7554adbef7aaef1721bf751a96385349037de341a8c09f3adae7ce5a20",
			aliceHash:  "a13a84314a8d571b5218ca26194fe2f38b5f43eb3ac94203c448f9940df2fdb2",
			bobPrv:     "afbce51fa32963574cdf52b7c48f59ce8016de95a9a3f9e5e0974ab10c98c30c",
			bobHash:    "6f7c5716c08fca79725beb4afaf2a48fd2fa547536d267f2b869b6ced5fddfa4",
			secretHash: "c9b2ad43f1aa70185f94dbc207ab4a147002f8aac5cf2fcec9d771a36f5f7a91",
		},
		{ // 04-pkey.t:245-254.
			name:       "id-tc26-gost-3410-2012-256-paramSetC",
			curve:      curve("1.2.643.7.1.2.1.1.3"),
			kek:        KEK2012256,
			alg:        "301706082a85030701010101300b06092a8503070102010103",
			alicePrv:   "eaf5719445f2c33eb0e230d3d472e9ebbd4c08e3a1413b6114fa893c6b50c037",
			aliceHash:  "c352cf32ce4fd12a294ac62f3e44808cc7b21178093ba454b447a9ab4395d9be",
			bobPrv:     "169baf7eadf9c64c3676e0c476f4872332cb8f8630504facf13ef518401ac62e",
			bobHash:    "27e3afdcb9f191b0465ae7d28245cee6ca44d537a7c67d938933cf2012ec71a6",
			secretHash: "43c9f321b3659ee5108f0bcd5527f403d445f486c9e492768f46a82359ee0385",
		},
		{ // 04-pkey.t:255-264.
			name:       "id-tc26-gost-3410-2012-256-paramSetD",
			curve:      curve("1.2.643.7.1.2.1.1.4"),
			kek:        KEK2012256,
			alg:        "301706082a85030701010101300b06092a8503070102010104",
			alicePrv:   "679b397532eb588805c19996b7196e6c2ba2b39e9b7a5798bec40977e910e15d",
			aliceHash:  "ebfb18e801fe2d41462c52571b1805e34993910b29f75a7a5517d3190b5d9d1d",
			bobPrv:     "69a7b6a753580c71a2bf073010cc06d41d75b692e87a87db7aee2ebb7887c081",
			bobHash:    "902a174ace21dc8ecf94e6a7e84cde115f902484e2c37d1d2652b1ef0a402dfc",
			secretHash: "3af2a69e68cd444acc269e75edb90dfe01b8f3d9f97fe7c8b36841df9a2771a1",
		},
		{ // 04-pkey.t:265-274; 512-bit key, derive still uses Streebog-256.
			name:  "id-tc26-gost-3410-2012-512-paramSetA",
			curve: curve("1.2.643.7.1.2.1.2.1"),
			kek:   KEK2012256,
			alg:   "302106082a85030701010102301506092a850307010201020106082a85030701010203",
			alicePrv: "55bcf993ff198fc5db4c4b65bfd6caf62f056886e6f8d37d902a76c026e26b0e" +
				"805ef74189094c8fb8521afec0756f76f1546cceaf4497073add541c63376793",
			aliceHash: "8bb6886e74a3d04ec0cbbe799f2494fd577f3bd9b8c06d7ec4cfa7c597d2d0ae",
			bobPrv: "49ea2874607adfd11391211f38b4c5913a33284a4c5409453e0bcae9f3a50fdb" +
				"b5fc84d45c1a0445e6b647e1c6dd8362f35c1332a4f4363abd5a76d0be0231ea",
			bobHash:    "e88ba18821e6a86787cb225ea9b731821efb9e07bdcfb7b0b8f78c70d4e88c2b",
			secretHash: "4d032ae84928991a48d83fc462da4d21173d8e832a3b30df71a6974f66e377a8",
		},
		{ // 04-pkey.t:275-284.
			name:  "id-tc26-gost-3410-2012-512-paramSetB",
			curve: curve("1.2.643.7.1.2.1.2.2"),
			kek:   KEK2012256,
			alg:   "302106082a85030701010102301506092a850307010201020206082a85030701010203",
			alicePrv: "bd02aed5f976d4d517bdd5a562d46cdc1b38656f6f425575adfd43d6b7d151dc" +
				"63b82d80df1743f51a14ba9ccae8478d16485331b67e7ae4135f03c537aca46c",
			aliceHash: "6c9f8cb350dcea5e673fe29950d9e5a041b005ca81d1236d19ba658dcbfdce01",
			bobPrv: "f88f08f44d05cf470a1b6d501e7ed596e1c1f63df8f2578599e5cb7c6512fa32" +
				"ea9657a6b4239b47b28b5b76e4cc7f848aa5db2cd326f892ec99e1afe3f9ef61",
			bobHash:    "f7071ed951ac98570a5f9d299bf5a61d3dcb8082e8733b1571164ce6b54b2d8f",
			secretHash: "f37881bf843ecee4f0935c4f7653d4cb48b8db6a50394f89792dad899765d7d9",
		},
		{ // 04-pkey.t:285-297; cofactor-4 curve, carries a Malice key.
			name:  "id-tc26-gost-3410-2012-512-paramSetC",
			curve: curve("1.2.643.7.1.2.1.2.3"),
			kek:   KEK2012256,
			alg:   "301706082a85030701010102300b06092a8503070102010203",
			alicePrv: "3bf45296ecca85e2940926fa4084a77d624c2c15707371a52162ddcdd4ab8957" +
				"a9f9689e3e91a25fb93dd86e1b70596ccd22c21d5d46516811063b6704c32b1a",
			aliceHash: "fa92c3898642b419b320b15a8285d6d01ae3a22cadc791b9ba52d12919e7008d",
			bobPrv: "2208d35000c9eeaf8106f1e483a6be568c96a81eab92b0adf0c9d0ab18cdc275" +
				"b69ad248ae8f99b4331d7a568c3b030bc6d83be52892fc1e0c2e06a5a50da61a",
			bobHash:    "6e1db0da8832660fbf761119e41d356a1599686a157c9a598b8e18b56cb09791",
			secretHash: "2df0dfa8d437689d41fad965f13ea28ce27c29dd84514b376ea6ad9f0c7e3ece",
			malicePub: "8f740111dba626ef70d251705a9932c9727b5d577a19ed1471ffe2237f5dc69c" +
				"5dfaa37ea2f2d102d77b89a8e3a6ba31240063edba2eb2138889355534b8ceb2" +
				"1e62043391f473cd5277f5500fcc975b587218066f4cc73e53fea86b7d1853d6" +
				"18efeb7be7d7750885739cf9aaf42f956c0029c8308c163b989ca0ff9c286c18",
		},
		{ // 04-pkey.t:298-307; Bob's scalar exercises the upper range boundary.
			name:       "id-tc26-gost-3410-2012-256-paramSetA-rangetest",
			curve:      curve("1.2.643.7.1.2.1.1.1"),
			kek:        KEK2012256,
			alg:        "301706082a85030701010101300b06092a8503070102010101",
			alicePrv:   "f9faed9e6d8c10f620d85879a27f85de1a08f63a28c9baae18b1b4cda07dfe07",
			aliceHash:  "a04b252bedc05f69fc92d8e985b52f0f984bccf3ef9f980ac7aca85f5ef11987",
			bobPrv:     "660c366c55af15c135667bc8dfcdd80f00000000000000000000000000000040",
			bobHash:    "29132b8efb7b21a15133e51c70599031ea813cca86edb0985e86f331493b3d73",
			secretHash: "7206480037eb130595c0ed350046af8c96b0fc5bfb4030be65dbf3e207a25de2",
		},
		{ // 04-pkey.t:308-317; Bob's scalar exercises the upper range boundary.
			name:  "id-tc26-gost-3410-2012-512-paramSetC-rangetest",
			curve: curve("1.2.643.7.1.2.1.2.3"),
			kek:   KEK2012256,
			alg:   "301706082a85030701010102300b06092a8503070102010203",
			alicePrv: "3bf45296ecca85e2940926fa4084a77d624c2c15707371a52162ddcdd4ab8957" +
				"a9f9689e3e91a25fb93dd86e1b70596ccd22c21d5d46516811063b6704c32b1a",
			aliceHash: "fa92c3898642b419b320b15a8285d6d01ae3a22cadc791b9ba52d12919e7008d",
			bobPrv: "ec23f047ef3c629426a169a7e7a9edc82c504751ffa9334c00ab0665a4db8cc9" +
				"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f",
			bobHash:    "fbcd6e72572335d291be497b7bfb264138ab7b2ecca00bc7a9fd90ad7557c0cc",
			secretHash: "8e5b7bd8b3680d3dc33627c5bed85fdeb4e1ba67307714eb260412ddbb4bb87e",
		},
	}

	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()

			alicePrv := mustHex(t, f.alicePrv)
			bobPrv := mustHex(t, f.bobPrv)

			// Public keys + their SPKI hashes (04-pkey.t:326-334).
			alicePub, err := DeriveQLE(f.curve, alicePrv)
			if err != nil {
				t.Fatalf("DeriveQLE(alice): %v", err)
			}

			bobPub, err := DeriveQLE(f.curve, bobPrv)
			if err != nil {
				t.Fatalf("DeriveQLE(bob): %v", err)
			}

			for _, side := range []struct {
				who  string
				pub  []byte
				want string
			}{{"alice", alicePub, f.aliceHash}, {"bob", bobPub, f.bobHash}} {
				spki := derTLV(0x30, append(mustHex(t, f.alg),
					derTLV(0x03, append([]byte{0x00}, derTLV(0x04, side.pub)...))...))
				if got := sha256.Sum256(spki); hex.EncodeToString(got[:]) != side.want {
					t.Errorf("%s SPKI hash = %x, want %s", side.who, got, side.want)
				}
			}

			// Shared key, both directions (04-pkey.t:335-340).
			for _, side := range []struct {
				who      string
				prv, pub []byte
			}{{"alice", alicePrv, bobPub}, {"bob", bobPrv, alicePub}} {
				kek, err := f.kek(f.curve, side.prv, side.pub, ukm)
				if err != nil {
					t.Fatalf("%s KEK: %v", side.who, err)
				}

				if got := sha256.Sum256(kek); hex.EncodeToString(got[:]) != f.secretHash {
					t.Errorf("%s KEK hash = %x, want %s", side.who, got, f.secretHash)
				}
			}

			// Small-subgroup Malice key must be rejected (04-pkey.t:341-348).
			if f.malicePub != "" {
				malice := mustHex(t, f.malicePub)
				for _, side := range []struct {
					who string
					prv []byte
				}{{"alice", alicePrv}, {"bob", bobPrv}} {
					if _, err := f.kek(f.curve, side.prv, malice, ukm); err == nil {
						t.Errorf("%s vs Malice: derive succeeded, want error", side.who)
					}
				}
			}
		})
	}
}

// TestCofactorReject verifies that a caller-supplied curve whose Cofactor is
// not 1 or 4 causes KEK2012256 to return errUnsupportedCofactor rather than
// silently computing a wrong KEK (R2-VKO-01).
func TestCofactorReject(t *testing.T) {
	t.Parallel()

	// Build a minimal syntactically-valid curve with an unsupported cofactor.
	// We borrow the 2001-TestParamSet constants (Cofactor 1 in production) and
	// override Cofactor to 2, 0, and 8 in turn. The override must be caught
	// before any scalar-multiplication, so we only need a structurally valid curve
	// — the KEK computation must not return (result, nil).
	base := curve2001Test()

	for _, badCofactor := range []int{0, 2, 8} {
		// Fresh curve instance so we don't copy base's embedded sync.Once; base
		// keeps its original Cofactor 1 for the deriveQ call below.
		c := curve2001Test()

		c.Cofactor = badCofactor

		// Any syntactically valid key material will do; reuse the KAT#1 scalars.
		d1 := mustHex(t, "1df129e43dab345b68f6a852f4162dc69f36b2f84717d08755cc5c44150bf928")
		d2 := mustHex(t, "5b9356c6474f913f1e83885ea0edd5df1a43fd9d799d219093241157ac9ed473")
		ukm := mustHex(t, "5172be25f852a233")

		q2 := deriveQ(t, base, d2) // derive on original curve (cofactor 1).

		_, err := KEK2012256(c, d1, q2, ukm)
		if err == nil {
			t.Errorf("Cofactor=%d: expected error, got nil", badCofactor)

			continue
		}

		if !errors.Is(err, errUnsupportedCofactor) {
			t.Errorf("Cofactor=%d: got %v, want errUnsupportedCofactor", badCofactor, err)
		}
	}
}

// TestCofactorRegression is a regression guard verifying that the cofactor-1
// and cofactor-4 paths still produce exactly the same KEK bytes after the
// R2-VKO-01 hardening change. It re-runs representative rows from
// TestKAT_Engine04PkeyDerive (one cofactor-1 curve, two cofactor-4 curves)
// and asserts the shared key SHA-256 is byte-for-byte unchanged.
func TestCofactorRegression(t *testing.T) {
	t.Parallel()

	ukm := mustHex(t, "0100000000000000")
	getCurve := func(oid string) *gost3410curves.Curve {
		c, err := gost3410curves.CurveByOID(oid)
		if err != nil {
			t.Fatalf("CurveByOID(%s): %v", oid, err)
		}

		return c
	}

	type row struct {
		name       string
		c          *gost3410curves.Curve
		kek        func(c *gost3410curves.Curve, prv, pub, ukm []byte) ([]byte, error)
		alicePrv   string
		bobPrv     string
		secretHash string // SHA-256 of KEK, pinned from TestKAT_Engine04PkeyDerive.
	}

	rows := []row{
		{
			// cofactor 1 — CryptoPro-C (tc26-256-D) — guards the h=1 path.
			// Vectors: 04-pkey.t:192-201.
			name:       "CryptoPro-C/cofactor-1",
			c:          getCurve("1.2.643.2.2.35.3"),
			kek:        KEK2001,
			alicePrv:   "3518d13a65b308efc78d8df6b9b3520977a309457824c9bae862c4fb06142511",
			bobPrv:     "67e0a6a5840afd4ea6e6772f8ab8660a661934b4f0dc0f5a0088a3ad4e6a5320",
			secretHash: "d61f1f55a1ad012884b969dbe2550f38f2356a029e5d8af07d50d10ca9812c58",
		},
		{
			// cofactor 4 — tc26-256-A — guards the h=4 path for 256-bit curves.
			// Vectors: 04-pkey.t:222-234.
			name:       "tc26-256-A/cofactor-4",
			c:          getCurve("1.2.643.7.1.2.1.1.1"),
			kek:        KEK2012256,
			alicePrv:   "f9faed9e6d8c10f620d85879a27f85de1a08f63a28c9baae18b1b4cda07dfe07",
			bobPrv:     "d5c1776fab5cdd0419b35631b558e05047f764c02cc5e8a48889591f4150ac2a",
			secretHash: "e9f7c57547fa0cd3c9942c62f9c74a553626d5f9810975a476825cd6f22a4e86",
		},
		{
			// cofactor 4 — tc26-512-C — guards the h=4 path for 512-bit curves.
			// Vectors: 04-pkey.t:285-297.
			name: "tc26-512-C/cofactor-4",
			c:    getCurve("1.2.643.7.1.2.1.2.3"),
			kek:  KEK2012256,
			alicePrv: "3bf45296ecca85e2940926fa4084a77d624c2c15707371a52162ddcdd4ab8957" +
				"a9f9689e3e91a25fb93dd86e1b70596ccd22c21d5d46516811063b6704c32b1a",
			bobPrv: "2208d35000c9eeaf8106f1e483a6be568c96a81eab92b0adf0c9d0ab18cdc275" +
				"b69ad248ae8f99b4331d7a568c3b030bc6d83be52892fc1e0c2e06a5a50da61a",
			secretHash: "2df0dfa8d437689d41fad965f13ea28ce27c29dd84514b376ea6ad9f0c7e3ece",
		},
	}

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			t.Parallel()

			alicePrv := mustHex(t, r.alicePrv)
			bobPrv := mustHex(t, r.bobPrv)

			alicePub, err := DeriveQLE(r.c, alicePrv)
			if err != nil {
				t.Fatalf("DeriveQLE(alice): %v", err)
			}

			bobPub, err := DeriveQLE(r.c, bobPrv)
			if err != nil {
				t.Fatalf("DeriveQLE(bob): %v", err)
			}

			kekHashHex := func(kekBytes []byte) string {
				h := sha256.Sum256(kekBytes)
				return hex.EncodeToString(h[:])
			}

			got, err := r.kek(r.c, alicePrv, bobPub, ukm)
			if err != nil {
				t.Fatalf("alice KEK: %v", err)
			}

			if kekHashHex(got) != r.secretHash {
				t.Errorf("alice KEK hash = %s, want %s", kekHashHex(got), r.secretHash)
			}

			got, err = r.kek(r.c, bobPrv, alicePub, ukm)
			if err != nil {
				t.Fatalf("bob KEK: %v", err)
			}

			if kekHashHex(got) != r.secretHash {
				t.Errorf("bob KEK hash = %s, want %s", kekHashHex(got), r.secretHash)
			}
		})
	}
}

// TestUKMEndianness pins guide D1: wire UKM 1d80603c8544c727 → 0x27c744853c60801d.
func TestUKMEndianness(t *testing.T) {
	t.Parallel()

	got := leBytes2big(mustHex(t, "1d80603c8544c727"))
	if got.Text(16) != "27c744853c60801d" {
		t.Fatalf("UKM LE decode: got %s want 27c744853c60801d", got.Text(16))
	}
}

// TestReverseInverse pins guide step 2: reverse is its own inverse.
func TestReverseInverse(t *testing.T) {
	t.Parallel()

	b := []byte{1, 2, 3, 4, 5, 6, 7}
	if !bytes.Equal(reverse(reverse(b)), b) {
		t.Fatal("reverse is not self-inverse")
	}
}

// Compile-time interface assertions: every hash the KEK pipeline drives must
// satisfy hash.Hash.
var (
	_ hash.Hash = streebogNew256()
	_ hash.Hash = streebogNew512()
	_ hash.Hash = gostr341194New()
)
