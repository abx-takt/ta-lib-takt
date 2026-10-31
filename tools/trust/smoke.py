#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only native API smoke; complete results go to stdout, not files."""

import argparse
import json
import struct


def arrays(values):
    return [{"shape": list(x.shape), "dtype": x.dtype.str, "all_bytes_hex": x.tobytes().hex()} for x in values]


def talib_case():
    import numpy as np
    import talib

    x = np.random.RandomState(19).normal(size=8192).cumsum() + 100
    result = []
    for period in (14, 20):
        result.extend((talib.CCI(x + 1, x - 1, x, timeperiod=period),
                       talib.EMA(x, timeperiod=period), talib.RSI(x, timeperiod=period),
                       talib.DX(x + 1, x - 1, x, timeperiod=period),
                       talib.ADX(x + 1, x - 1, x, timeperiod=period),
                       talib.ATR(x + 1, x - 1, x, timeperiod=period),
                       talib.SMA(x, timeperiod=period)))
    result.extend(talib.BBANDS(x))
    result.extend(talib.MACD(x))
    result.extend(talib.STOCH(x + 1, x - 1, x))
    result.append(talib.SAR(x + 1, x - 1))
    return {"package": "ta-lib-takt", "outputs": arrays(result), "indicator_arrays": len(result)}


def lightgbm_case():
    import numpy as np
    import lightgbm as lgb

    rng = np.random.RandomState(29)
    x = rng.normal(size=(8192, 8))
    y = x[:, 0] * 2 + x[:, 3] - x[:, 7] * 0.1
    booster = lgb.train({"objective": "regression", "num_threads": 1, "verbosity": -1,
                         "seed": 11, "force_col_wise": True, "num_leaves": 15},
                        lgb.Dataset(x, label=y), num_boost_round=20)
    outputs = [booster.predict(x, num_threads=1)]
    for column in range(8):
        edited = x.copy()
        edited[:, column] = rng.permutation(edited[:, column])
        outputs.append(booster.predict(edited, num_threads=1))
    return {"package": "lightgbm-takt", "outputs": arrays(outputs), "prediction_arrays": len(outputs)}


def quantlib_case():
    import QuantLib as ql

    today = ql.Date(15, ql.January, 2026)
    ql.Settings.instance().evaluationDate = today
    dc = ql.Actual365Fixed()
    spot = ql.QuoteHandle(ql.SimpleQuote(100))
    rate = ql.YieldTermStructureHandle(ql.FlatForward(today, 0.03, dc))
    div = ql.YieldTermStructureHandle(ql.FlatForward(today, 0.01, dc))
    results = []
    for sigma in (0.15, 0.20, 0.30):
        vol = ql.BlackVolTermStructureHandle(ql.BlackConstantVol(today, ql.NullCalendar(), sigma, dc))
        process = ql.BlackScholesMertonProcess(spot, div, rate, vol)
        option = ql.VanillaOption(ql.PlainVanillaPayoff(ql.Option.Call, 100),
                                  ql.EuropeanExercise(ql.Date(15, ql.January, 2027)))
        option.setPricingEngine(ql.MCEuropeanEngine(process, "pseudorandom", timeSteps=16,
                                                  requiredSamples=4096, seed=37))
        results.append(option.NPV())
        option.setPricingEngine(ql.AnalyticEuropeanEngine(process))
        results.append(option.NPV())
    return {"package": "quantlib-takt", "values": len(results),
            "all_float64_bytes_hex": b"".join(struct.pack("<d", x) for x in results).hex()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", choices=("ta-lib-takt", "lightgbm-takt", "quantlib-takt"))
    args = parser.parse_args()
    functions = {"ta-lib-takt": talib_case, "lightgbm-takt": lightgbm_case, "quantlib-takt": quantlib_case}
    print(json.dumps(functions[args.package](), sort_keys=True))
