using CSV
using DataFrames

function convert_unit(value, unit)
    factors = Dict(
        "ps" => 1e12,
        "ns" => 1e9,
        "\ub5s" => 1e6, "\u3bcs" => 1e6, # Handle alternative unicode points for greek mu
        "ms" => 1e3,
        "s" => 1e0
    )
    value * factors[unit]
end

function convert_unit(str)
    regex = r"\s*(\d+(?:\.\d+)?)\s*(\S+)\s*"
    (value, unit) = match(regex, str)
    convert_unit(parse(Float64, value), unit)
end

normalize_units(df) = mapcols(c -> map(convert_unit, c), df, cols=3:11)

function main()
    in_file = "./benchmarks_excel.csv"
    out_file = "./baseline.csv"
    benchmarks = CSV.read(in_file, DataFrame)
    benchmarks = normalize_units(benchmarks)
    CSV.write(out_file, benchmarks, delim=';')
end
