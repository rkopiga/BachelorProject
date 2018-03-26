package share

import (
	"testing"

	"github.com/dedis/kyber/group/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/dedis/kyber"
	"fmt"
	//"errors"
)

func TestSecretRecovery(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1
	poly := NewPriPoly(g, t, g.Scalar().Pick(g.RandomStream()))
	//shares := poly.Shares(n)
	polyh := NewPriPoly(g,t,nil)
	polyg, errAdd := poly.Add(polyh)
	if errAdd != nil{
		test.Fatal(errAdd)
	}

	sharesNewPoly := polyg.Shares(n)

	recovered, err := RecoverSecret(g, sharesNewPoly, t, n) //A changer shares
	if err != nil {
		test.Fatal(err)
	}

	if !recovered.Equal(polyg.Secret()) {
		test.Fatal("recovered secret does not match initial value")
	}
}


func TestSecretRecoveryDelete(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1
	poly := NewPriPoly(g, t, g.Scalar().Pick(g.RandomStream()))
	polyh := NewPriPoly(g,t,nil)
	polyg, errAdd := poly.Add(polyh)

	if errAdd != nil{
		test.Fatal(errAdd)
	}

	//shares := poly.Shares(n)
	sharesNewPoly := polyg.Shares(n)

	// Corrupt a few shares
	sharesNewPoly[2] = nil
	sharesNewPoly[5] = nil
	sharesNewPoly[7] = nil
	sharesNewPoly[8] = nil

	recovered, err := RecoverSecret(g, sharesNewPoly, t, n)
	if err != nil {
		test.Fatal(err)
	}

	if !recovered.Equal(polyg.Secret()) {
		test.Fatal("recovered secret does not match initial value")
	}
}

func TestSecretRecoveryDeleteFail(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1

	poly := NewPriPoly(g, t, g.Scalar().Pick(g.RandomStream()))
	polyh := NewPriPoly(g,t,nil)
	polyg, errAdd := poly.Add(polyh)

	if errAdd != nil{
		test.Fatal(errAdd)
	}
	//shares := poly.Shares(n)
	sharesNewPoly := polyg.Shares(n)

	// Corrupt one more share than acceptable
	sharesNewPoly[1] = nil
	sharesNewPoly[2] = nil
	sharesNewPoly[5] = nil
	sharesNewPoly[7] = nil
	sharesNewPoly[8] = nil

	_, err := RecoverSecret(g, sharesNewPoly, t, n)
	if err == nil {
		test.Fatal("recovered secret unexpectably")
	}
}

func TestSecretPolyEqual(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1

	p1 := NewPriPoly(g, t, nil)
	p2 := NewPriPoly(g, t, nil)
	p3 := NewPriPoly(g, t, nil)

	p12, _ := p1.Add(p2)
	p13, _ := p1.Add(p3)

	p123, _ := p12.Add(p3)
	p132, _ := p13.Add(p2)

	if !p123.Equal(p132) {
		test.Fatal("private polynomials not equal")
	}
}

func TestPublicCheck(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1

	priPoly := NewPriPoly(g, t, g.Scalar().Pick(g.RandomStream()))
	//priShares := priPoly.Shares(n)
	priPolyh := NewPriPoly(g,t,nil)
	priPolyg, errAdd := priPoly.Add(priPolyh)
	if errAdd != nil{
		test.Fatal(errAdd)
	}
	priSharesNew := priPolyg.Shares(n)
	//pubPoly := priPoly.Commit(nil)
	pubPolynew := priPolyg.Commit(g.Point().Pick(g.RandomStream()))

	for i, share := range priSharesNew {
		if !pubPolynew.Check(share) {
			test.Fatalf("private share %v not valid with respect to the public commitment polynomial", i)
		}
	}
}

func TestPublicRecovery(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1

	priPoly := NewPriPoly(g, t, g.Scalar().Pick(g.RandomStream())) //f()
	priPolyh := NewPriPoly(g,t,nil)
	priPolyg, errAdd := priPoly.Add(priPolyh)
	pubPoly := priPolyg.Commit(g.Point().Pick(g.RandomStream())) // F()
	pubShares := pubPoly.Shares(n) //F(i)

	if errAdd != nil{
		test.Fatal(errAdd)
	}

	recovered, err := RecoverCommit(g, pubShares, t, n)
	if err != nil {
		test.Fatal(err)
	}

	if !recovered.Equal(pubPoly.Commit()) {
		test.Fatal("recovered commit does not match initial value")
	}
}

func TestPublicRecoveryDelete(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1

	priPoly := NewPriPoly(g, t, g.Scalar().Pick(g.RandomStream()))
	priPolyh := NewPriPoly(g,t,nil)
	priPolyg, errAdd := priPoly.Add(priPolyh)
	pubPoly := priPolyg.Commit(g.Point().Pick(g.RandomStream()))
	shares  := pubPoly.Shares(n)

	if errAdd != nil{
		test.Fatal(errAdd)
	}

	// Corrupt a few shares
	shares[2] = nil
	shares[5] = nil
	shares[7] = nil
	shares[8] = nil

	recovered, err := RecoverCommit(g, shares, t, n)
	if err != nil {
		test.Fatal(err)
	}

	if !recovered.Equal(pubPoly.Commit()) {
		test.Fatal("recovered commit does not match initial value")
	}
}

func TestPublicRecoveryDeleteFail(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1

	priPoly := NewPriPoly(g, t, g.Scalar().Pick(g.RandomStream()))
	priPolyh := NewPriPoly(g,t,nil)
	priPolyg, errAdd := priPoly.Add(priPolyh)
	pubPoly := priPolyg.Commit(g.Point().Pick(g.RandomStream()))
	shares := pubPoly.Shares(n)

	if errAdd != nil{
		test.Fatal(errAdd)
	}

	// Corrupt one more share than acceptable
	shares[1] = nil
	shares[2] = nil
	shares[5] = nil
	shares[7] = nil
	shares[8] = nil

	_, err := RecoverCommit(g, shares, t, n)
	if err == nil {
		test.Fatal("recovered commit unexpectably")
	}
}

func TestPrivateAdd(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1

	p := NewPriPoly(g, t, nil)
	q := NewPriPoly(g, t, nil)

	r, err := p.Add(q)
	if err != nil {
		test.Fatal(err)
	}

	ps := p.Secret()
	qs := q.Secret()
	rs := g.Scalar().Add(ps, qs)

	if !rs.Equal(r.Secret()) {
		test.Fatal("addition of secret sharing polynomials failed")
	}
}

func TestPublicAdd(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1

	G := g.Point().Pick(g.RandomStream())
	H := g.Point().Pick(g.RandomStream())

	p := NewPriPoly(g, t, nil)
	q := NewPriPoly(g, t, nil)

	P := p.Commit(G)
	Q := q.Commit(H)

	R, err := P.Add(Q)
	if err != nil {
		test.Fatal(err)
	}

	shares := R.Shares(n)
	recovered, err := RecoverCommit(g, shares, t, n)
	if err != nil {
		test.Fatal(err)
	}

	x := P.Commit()
	y := Q.Commit()
	z := g.Point().Add(x, y)

	if !recovered.Equal(z) {
		test.Fatal("addition of public commitment polynomials failed")
	}
}

func TestPublicPolyEqual(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1

	G := g.Point().Pick(g.RandomStream())

	p1 := NewPriPoly(g, t, nil)
	p2 := NewPriPoly(g, t, nil)
	p3 := NewPriPoly(g, t, nil)

	P1 := p1.Commit(G)
	P2 := p2.Commit(G)
	P3 := p3.Commit(G)

	P12, _ := P1.Add(P2)
	P13, _ := P1.Add(P3)

	P123, _ := P12.Add(P3)
	P132, _ := P13.Add(P2)

	if !P123.Equal(P132) {
		test.Fatal("public polynomials not equal")
	}
}

func TestPriPolyMul(test *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1
	a := NewPriPoly(suite, t, nil)
	b := NewPriPoly(suite, t, nil)

	c := a.Mul(b)
	assert.Equal(test, len(a.coeffs)+len(b.coeffs)-1, len(c.coeffs))
	nul := suite.Scalar().Zero()
	for _, coeff := range c.coeffs {
		assert.NotEqual(test, nul.String(), coeff.String())
	}

	a0 := a.coeffs[0]
	b0 := b.coeffs[0]
	mul := suite.Scalar().Mul(b0, a0)
	c0 := c.coeffs[0]
	assert.Equal(test, c0.String(), mul.String())

	at := a.coeffs[len(a.coeffs)-1]
	bt := b.coeffs[len(b.coeffs)-1]
	mul = suite.Scalar().Mul(at, bt)
	ct := c.coeffs[len(c.coeffs)-1]
	assert.Equal(test, ct.String(), mul.String())
}

func TestRecoverPriPoly(test *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1
	a := NewPriPoly(suite, t, nil)

	shares := a.Shares(n)
	reverses := make([]*PriShare, len(shares))
	l := len(shares) - 1
	for i := range shares {
		reverses[l-i] = shares[i]
	}
	recovered, err := RecoverPriPoly(suite, shares, t, n)
	assert.Nil(test, err)

	reverseRecovered, err := RecoverPriPoly(suite, reverses, t, n)
	assert.Nil(test, err)

	for i := 0; i < t; i++ {
		assert.Equal(test, recovered.Eval(i).V.String(), a.Eval(i).V.String())
		assert.Equal(test, reverseRecovered.Eval(i).V.String(), a.Eval(i).V.String())
	}
}

//========================================================================== KOPIGA VERSION ========================================================================

func TestSecretRecoveryDKG(test *testing.T) {
	g := edwards25519.NewBlakeSHA256Ed25519()
	n := 10
	t := n/2 + 1

	poly := PriPolys(n, g, t) //tableau avec les polynomials secrets

	sharesMat := make([][]*PriShare, n)

	for i := 0; i < n; i++ {
		sharesMat[i] = poly[i].Shares(n)
	}

	sumshare := make([]*PriShare, n) //list des shares
	for j := 0; j < n; j++ {
		sum := &PriShare{j, g.Scalar().Zero()}
		for i:= 0; i < n ; i++ {
			sum = sum.AddShares(sharesMat[i][j], g)
		}
		sumshare[j] = sum
	}

	// totShares are computed. Now using these shares we can recover the coefficients of ftot

	coeffs := make([]kyber.Scalar, t)
	for i := 0; i < t; i++ {
		coeffs[i] = g.Scalar().Zero()
	}
	p := &PriPoly{s: g, coeffs: coeffs}
	for i:= 0; i < n; i++ {
		p, _ = p.Add(poly[i])			//ftot(x)
	}

	// the last coeff of ftot(x) must correspond to the last coeff of the intrapolated function
	recovered, err := RecoverSecret(g, sumshare, t, n)
	if err != nil {
		test.Fatal(err)
	}

	if !recovered.Equal(p.Secret()) {
		test.Fatal("recovered secret does not match initial value")
	}

}

func PriPolys(n int, s Suite, t int) []*PriPoly {
	privatePolys := make([]*PriPoly, n)
	for i := range privatePolys {
		privatePolys[i] = NewPriPoly(s, t, s.Scalar().Pick(s.RandomStream()))
	}
	return privatePolys
}

func (p *PriShare) AddShares(q *PriShare, suite Suite) (*PriShare){
	if(p.I==q.I) {return &PriShare{p.I, suite.Scalar().Add(p.V,q.V)}}
	return nil
}

