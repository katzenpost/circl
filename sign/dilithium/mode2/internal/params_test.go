package internal

import (
	"testing"

	"github.com/katzenpost/circl/sign/dilithium/internal/common"
)

// Tests specific to the current mode

func TestVectorDeriveUniformLeqEta(t *testing.T) {
	var p common.Poly
	var seed [64]byte
	p2 := common.Poly{
		8380415, 1, 8380415, 8380416, 1, 8380415, 8380416, 8380415,
		8380415, 8380416, 8380416, 2, 2, 1, 8380415, 8380415,
		8380416, 1, 8380416, 8380415, 2, 0, 0, 1, 1, 2, 2, 8380415,
		0, 8380416, 8380416, 8380416, 8380415, 1, 2, 0, 1, 8380415,
		0, 1, 8380415, 1, 0, 8380415, 2, 1, 2, 0, 1, 0, 8380416,
		1, 8380416, 1, 0, 1, 1, 0, 1, 8380416, 0, 0, 8380416,
		8380415, 8380416, 2, 0, 0, 8380415, 1, 1, 0, 0, 1, 8380415,
		1, 8380416, 1, 8380415, 8380416, 8380416, 8380415, 0, 1,
		8380415, 8380415, 1, 8380415, 0, 2, 2, 8380415, 1, 2,
		8380415, 8380415, 0, 2, 2, 1, 8380415, 8380416, 0, 8380415,
		2, 1, 8380415, 2, 2, 8380416, 8380416, 0, 8380416, 0, 2,
		8380416, 1, 8380415, 8380416, 8380415, 1, 8380416, 8380416,
		2, 2, 0, 0, 0, 8380415, 8380415, 2, 8380416, 2, 2, 8380415,
		8380415, 2, 2, 2, 8380415, 1, 2, 1, 2, 8380415, 0, 2, 1,
		8380415, 2, 8380415, 8380415, 8380416, 0, 8380416, 8380415,
		8380415, 8380416, 8380416, 2, 8380416, 2, 0, 0, 1, 1, 1,
		8380416, 0, 8380416, 8380416, 1, 1, 1, 0, 8380416, 2, 0,
		8380415, 8380415, 0, 0, 2, 8380416, 1, 0, 0, 8380415,
		8380415, 1, 0, 8380416, 1, 2, 8380415, 0, 8380416, 8380415,
		1, 1, 0, 1, 8380416, 8380415, 1, 0, 0, 8380416, 1, 0, 2,
		8380416, 2, 2, 0, 0, 1, 1, 2, 8380415, 2, 8380416, 8380416,
		2, 1, 2, 8380416, 8380415, 8380415, 8380415, 0, 8380416,
		1, 0, 2, 8380416, 2, 8380415, 8380415, 2, 2, 8380415,
		8380416, 0, 8380415, 8380415, 0, 2, 8380415, 1, 8380415,
		8380415, 1, 1, 8380416, 8380416,
	}
	for i := 0; i < 64; i++ {
		seed[i] = byte(i)
	}
	PolyDeriveUniformLeqEta(&p, &seed, 30000)
	p.Normalize()
	if p != p2 {
		t.Fatalf("%v != %v", p, p2)
	}
}

func TestVectorDeriveUniformLeGamma1(t *testing.T) {
	var p, p2 common.Poly
	var seed [64]byte
	p2 = common.Poly{
		24652, 8360658, 8306, 8359852, 10689, 106730, 8321632,
		8295173, 8263144, 8362203, 8270304, 86550, 8352484, 112252,
		8326622, 8263346, 1209, 8357433, 8276262, 106912, 111719,
		8266410, 8001, 8249719, 8298833, 108641, 127143, 74178,
		8266405, 27781, 128456, 8359778, 8337159, 8336455, 8380097,
		8339564, 8275392, 8298630, 8257822, 5932, 233, 8367273,
		8335081, 8257869, 8350642, 8317253, 8256389, 8341263,
		8360509, 8368380, 33767, 81445, 8265057, 8353702, 8270465,
		61206, 8309816, 8281560, 8295763, 6244, 8353442, 8378970,
		72579, 8351700, 8341053, 104835, 8344333, 8313546, 8373167,
		61430, 8339993, 113603, 8254406, 8302777, 99473, 8342736,
		54456, 65097, 8255826, 8329025, 23031, 8328165, 57608,
		30426, 98210, 8264076, 8267955, 8351117, 22980, 8302860,
		42373, 8349139, 6523, 8375937, 13127, 8270690, 40178, 105482,
		74831, 8261990, 8306279, 5925, 8260573, 55220, 110952,
		8273377, 8267217, 8275798, 124100, 119164, 8360113, 67060,
		8351620, 8364798, 59495, 8362276, 8285770, 8313138, 37321,
		8379867, 56428, 45742, 46037, 18715, 8330440, 99372, 8270907,
		8341031, 49485, 63571, 111869, 8339624, 8311220, 8277176,
		8357815, 60583, 8356010, 98423, 8360878, 84829, 8264301,
		63134, 8321092, 8279722, 8352609, 8261763, 62169, 8317324,
		122488, 8373120, 8337853, 8300028, 50829, 64411, 8330934,
		8363377, 91994, 7023, 5142, 94655, 8335648, 28257, 129346,
		68918, 14273, 27103, 8323037, 104538, 8307539, 55606, 94886,
		8272263, 77952, 8314535, 9544, 8253819, 46445, 8267118,
		85028, 8357851, 105779, 32474, 8256782, 89388, 8265113,
		8291502, 48133, 57355, 60120, 8281124, 8346594, 8255737,
		41780, 67374, 80423, 86222, 8334625, 97415, 8288685, 81515,
		98856, 8300724, 36434, 89698, 4154, 21804, 70249, 102464,
		101103, 8277794, 72647, 67640, 8323688, 61139, 91234, 74869,
		8368270, 8367469, 8373445, 8249916, 86939, 8254257, 12306,
		8270129, 48350, 8345018, 8364752, 8327455, 14568, 8252624,
		62944, 32561, 8258436, 96011, 8331595, 33812, 8303001, 2233,
		28847, 13235, 23003, 40644, 8279857, 8261616, 46409, 8369530,
		112030, 97207, 8269039, 102924, 75641, 85486, 8358768,
		65209, 92920, 34770,
	}
	for i := 0; i < 64; i++ {
		seed[i] = byte(i)
	}
	PolyDeriveUniformLeGamma1(&p, &seed, 30000)
	p.Normalize()
	if p != p2 {
		t.Fatalf("%v != %v", p, p2)
	}
}
