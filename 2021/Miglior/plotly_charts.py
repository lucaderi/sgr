import dash
import dash.html as html
import pandas
import plotly.graph_objs as go

from dash import dcc
from dash.dependencies import Input, Output

bgcolor = 'floralwhite'
actual_style = dict([('color', '#ff0000'), ('dash', 'solid')])
forecast_style = dict([('color', '#d63eb5'), ('dash', 'dot')])
conf_style = dict([('color', '#0b8c16'), ('dash', 'solid')])
quantile_style = dict([('color', 'mediumpurple'), ('dash', 'dot')])
marker_style = dict(size=50, color='mediumpurple', line=dict(color='purple', width=1))

page_style = {
    'font-family': 'arial',
    'text-align': 'center',
    'background-color': bgcolor
}

app = dash.Dash()
df: pandas.DataFrame
anomaly_df: pandas.DataFrame
quantiles = {}


def df_callback(new_ref, new_anomaly_ref, quantiles_ref):
    global df
    global anomaly_df
    global quantiles

    df = new_ref
    anomaly_df = new_anomaly_ref

    if quantiles_ref is not None:
        quantiles = quantiles_ref


def begin(address, port, dataframe):
    global df
    df = dataframe

    layout = html.Div(children=[
        html.Div([
            html.H1(children='Time series Anomaly Analysis'),
            html.Div(children='Chart 1: Candlestick Chart'),
            dcc.Graph(id='candlestick'),
            dcc.Interval(
                id='interval-candles',
                interval=10 * 1000,  # in milliseconds
                n_intervals=0
            )
        ]),
        html.Div([
            html.Div(children='Chart 2: Volumes Forecast Chart', style=page_style),
            dcc.Graph(id='volume'),
            dcc.Interval(
                id='interval-volume',
                interval=10 * 1000,  # in milliseconds
                n_intervals=0
            )
        ]),
        html.Div([
            html.Div(children='Chart 3: Open Values Forecast Chart', style=page_style),
            dcc.Graph(id='open'),
            dcc.Interval(
                id='interval-open',
                interval=10 * 1000,  # in milliseconds
                n_intervals=0
            )
        ]),
        html.Div([
            html.Div(children='Chart 4: Close Forecast Chart', style=page_style),
            dcc.Graph(id='close'),
            dcc.Interval(
                id='interval-close',
                interval=10 * 1000,  # in milliseconds
                n_intervals=0
            )
        ]),
    ],
        style=page_style
    )

    # run dash app to show charts
    app.layout = layout
    app.run_server(address, port)


@app.callback(Output('candlestick', 'figure'), Input('interval-candles', 'n_intervals'))
def candlestick_chart(n):
    fig0 = go.Figure(data=[go.Candlestick(
        x=df['date'],
        open=df['open'],
        close=df['close'],
        high=df['high'],
        low=df['low'],
    )])
    try:
        fig0.add_trace(
            go.Scatter(
                x=anomaly_df['date'],
                y=anomaly_df['open'],
                mode='markers',
                opacity=0.5,
                marker=marker_style,
                name='Anomaly Marker'
            )
        )
    except KeyError:
        pass

    fig0.update_layout(xaxis_rangeslider_visible=False, paper_bgcolor=bgcolor)
    return fig0


@app.callback(Output('volume', 'figure'), Input('interval-volume', 'n_intervals'))
def volume_chart(n):
    fig1 = go.Figure()

    # Volume chart
    fig1.add_trace(go.Scatter(x=df['date'], y=df['volume'], line=actual_style, name='actual volume'))
    fig1.add_trace(go.Scatter(x=df['date'], y=df['volume_forecast'], line=forecast_style, name='forecast volume'))
    fig1.add_trace(
        go.Scatter(x=df['date'], y=df['vol_confidence_lower_band'], line=conf_style, name='lower confidence open'))
    fig1.add_trace(
        go.Scatter(x=df['date'], y=df['vol_confidence_upper_band'], line=conf_style, name='upper confidence open'))
    try:
        fig1.add_hline(y=quantiles['volume'], line=quantile_style)
    except KeyError:
        pass

    try:
        fig1.add_trace(
            go.Scatter(
                x=anomaly_df['date'],
                y=anomaly_df['volume'],
                mode='markers',
                opacity=0.5,
                marker=marker_style,
                name='Anomaly Marker'
            )
        )
    except KeyError:
        pass

    fig1.update_layout(paper_bgcolor=bgcolor)
    return fig1


@app.callback(Output('close', 'figure'), Input('interval-close', 'n_intervals'))
def close_chart(n):
    fig2 = go.Figure()

    # Close chart
    fig2.add_trace(go.Scatter(x=df['date'], y=df['close'], line=actual_style, name='actual close'))
    fig2.add_trace(go.Scatter(x=df['date'], y=df['close_forecast'], line=forecast_style, name='forecast close'))
    fig2.add_trace(
        go.Scatter(x=df['date'], y=df['close_confidence_upper_band'], line=conf_style, name='upper confidence'))
    fig2.add_trace(
        go.Scatter(x=df['date'], y=df['close_confidence_lower_band'], line=conf_style, name='lower confidence'))

    try:
        fig2.add_hline(y=quantiles['close'], line=quantile_style)
    except KeyError:
        pass

    try:
        fig2.add_trace(
            go.Scatter(
                x=anomaly_df['date'],
                y=anomaly_df['close'],
                mode='markers',
                opacity=0.5,
                marker=marker_style,
                name='Anomaly Marker'
            )
        )
    except KeyError:
        pass

    fig2.update_layout(paper_bgcolor=bgcolor)
    return fig2


@app.callback(Output('open', 'figure'), Input('interval-open', 'n_intervals'))
def open_chart(n):
    fig3 = go.Figure()

    # Open chart
    fig3.add_trace(go.Scatter(x=df['date'], y=df['open'], line=actual_style, name='actual open'))
    fig3.add_trace(go.Scatter(x=df['date'], y=df['open_forecast'], line=forecast_style, name='forecast open'))
    fig3.add_trace(
        go.Scatter(x=df['date'], y=df['op_confidence_upper_band'], line=conf_style, name='upper confidence'))
    fig3.add_trace(
        go.Scatter(x=df['date'], y=df['op_confidence_lower_band'], line=conf_style, name='lower confidence'))

    try:
        fig3.add_hline(y=quantiles['open'], line=quantile_style)
    except KeyError:
        pass


    try:
        fig3.add_trace(
            go.Scatter(
                x=anomaly_df['date'],
                y=anomaly_df['open'],
                mode='markers',
                opacity=0.5,
                marker=marker_style,
                name='Anomaly Marker'
            )
        )
    except KeyError:
        pass

    fig3.update_layout(paper_bgcolor=bgcolor)
    return fig3