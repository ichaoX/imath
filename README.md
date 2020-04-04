# imath

imath is a command shell for imitation Mathematica kernel.

```
$ ./imath.py
Mathematica 12.0.0 Kernel for Linux x86 (64-bit)
Copyright 1988-2019 Wolfram Research, Inc.

In[1]:= Fourier
Fourier                   FourierMatrix
FourierCoefficient        FourierParameters
FourierCosCoefficient     FourierSequenceTransform
FourierCosSeries          FourierSeries
FourierCosTransform       FourierSinCoefficient
FourierDCT                FourierSinSeries
FourierDCTFilter          FourierSinTransform
FourierDCTMatrix          FourierTransform
FourierDST                FourierTrigSeries
FourierDSTMatrix          
In[1]:= FourierSeries[x y,{x,y},{1,1}]

          I (-x - y)    I (x - y)    I (-x + y)    I (x + y)
Out[1]= -E           + E          + E           - E

In[2]:= 
```

![demo](doc/example.jpg?raw=true)

## Requirements

The following dependencies are necessary:

* Python 2.7 or higher
* Mathematica 3.0 or higher / Wolfram Engine

### Windows

```sh
pip install pyreadline
```
