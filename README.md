# ta-lib-takt

TA-Lib 0.8.1 for Python with a faster core. The Python package is the official TA-Lib wrapper,
unchanged (`import talib`); only the C library inside it is replaced by a TAKT build of TA-Lib 0.8.1.
Every output is identical to the official library, bit for bit.

## Install

```sh
pip uninstall -y TA-Lib      # both packages provide `import talib`
pip install ta-lib-takt
```

Linux x86-64 with glibc 2.29 or newer, Python 3.9 to 3.14. The faster paths need AVX2 and FMA
(Intel Haswell, AMD Zen or newer); on other CPUs the original code runs. Gains need long series:
for short ones (a few thousand bars) the original code runs at the original speed.

## How much faster

A parameter sweep (99 periods over one million bars) through the unchanged Python wrapper, the whole
process timed, against the official TA-Lib 0.8.1 wheel from PyPI. AMD Zen 3 (Threadripper PRO 5975WX),
7 interleaved rounds with takt-harness; the output was identical in every run:

| Indicator | Wall-time factor | Indicator | Wall-time factor |
|---|---:|---|---:|
| CCI | 6.35× | EMA | 2.17× |
| DX | 2.81× | RSI | 2.03× |
| ADX | 2.80× | BBANDS | 1.23× |
| SAR | 2.58× | MACD | 1.20× |
| STOCH | 2.18× | ATR | 1.14× |

Called from C the same library is 2.3–7.4× faster on these seven indicators, on AMD Zen 3 and Zen 4.
All other TA-Lib functions run the original code. Full measurements, readings and the reproduction
steps: https://taktcycles.com/showcase/talib/README.html?src=github

## The same output, bit for bit

Every output array and both output indices match the official TA-Lib library: 4.59 million C API
calls and 40,824 calls through this Python wrapper were compared with zero differences, over random
walks, constant, alternating and volatile series, NaN and infinity inserts, magnitudes from 1e-300
to 1e300, lengths from 1 to one million and 20 periods. To check on your own data, compute the same
indicators in two virtual environments (one with `TA-Lib`, one with `ta-lib-takt`) and compare the
arrays with `numpy.array_equal` (NaN in the same places counts as equal: use `equal_nan=True`).

## Your own code, this fast?

TAKT speeds up the hot code of backtests, parameter sweeps and model training, with output identical
to the original, and measures the speedup before you pay. Free speed check:
https://taktcycles.com/?src=github#start · Measurements and updates: https://t.me/taktcycles

## Licence

The Python wrapper is TA-Lib's (BSD 2-clause, John Benediktsson). The C library is a modified build of
TA-Lib 0.8.1 (BSD 3-clause, Mario Fortier); the source of the modified functions is not published.
Both licences are included. This package is not affiliated with the TA-Lib project.

Questions, bugs, a function you want faster: https://github.com/abx-takt/ta-lib-takt/issues
