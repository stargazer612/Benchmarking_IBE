using DataFrames

function parseline(line)
    regex = r"test ([^\.]+) ... bench: \s* ([0123456789.,]+) (ps|ns|μs|ms|s)/iter \(\+\/- (\d+)\)"
    m = match(regex, line)
    if isnothing(m)
        return nothing
    end
    desc, time, unit, dev = m
    time = time |> filter(c -> c != ',') |> s -> parse(Float64, s)
    Dict("desc" => desc,
         "time" => time,
         "unit" => unit,
         "dev" => parse(Int, dev))
end

function parse_criterion_output(file)
    df = DataFrame(desc=String[], time=Int[], unit=String[], dev=Int[])
    for line in readlines(file)
        dict = parseline(line)
        if !isnothing(dict)
            push!(df, dict)
        end
    end
    df
end
