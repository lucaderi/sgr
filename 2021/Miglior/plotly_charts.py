import dash
import dash.html as html
import plotly.graph_objs as go

from dash import dcc

bgcolor = 'floralwhite'
actual_style = dict([('color', '#ff0000'), ('dash', 'solid')])
forecast_style = dict([('color', '#d63eb5'), ('dash', 'dot')])
conf_style = dict([('color', '#0b8c16'), ('dash', 'solid')])
quantile_style = dict([('color', 'mediumpurple'), ('dash', 'dot')])
marker_style = dict(size=50, color='mediumpurple', line=dict(color='purple', width=1))

page_style =\
    {
                'font-family': 'arial',
                'text-align': 'center',
                'background-color': bgcolor
    }


def plot_data(df, anomaly_df, quantile, address, port):

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

    fig1 = go.Figure()
    fig2 = go.Figure()
    fig3 = go.Figure()

    # Volume chart
    fig1.add_trace(go.Scatter(x=df['date'], y=df['volume'], line=actual_style, name='actual volume'))
    fig1.add_trace(go.Scatter(x=df['date'], y=df['volume_forecast'], line=forecast_style, name='forecast volume'))
    fig1.add_trace(
        go.Scatter(x=df['date'], y=df['vol_confidence_lower_band'], line=conf_style, name='lower confidence open'))
    fig1.add_trace(
        go.Scatter(x=df['date'], y=df['vol_confidence_upper_band'], line=conf_style, name='upper confidence open'))
    fig1.add_hline(y=df['volume'].quantile(quantile), line=quantile_style, name='{}th percentile'.format(quantile*100))
    fig1.update_layout(paper_bgcolor=bgcolor)

    # Close chart
    fig2.add_trace(go.Scatter(x=df['date'], y=df['close'], line=actual_style, name='actual close'))
    fig2.add_trace(go.Scatter(x=df['date'], y=df['close_forecast'], line=forecast_style, name='forecast close'))
    fig2.add_trace(
        go.Scatter(x=df['date'], y=df['close_confidence_upper_band'], line=conf_style, name='upper confidence'))
    fig2.add_trace(
        go.Scatter(x=df['date'], y=df['close_confidence_lower_band'], line=conf_style, name='lower confidence'))
    fig2.add_hline(y=df['close'].quantile(quantile), line=quantile_style,
                   name='{}th percentile'.format(quantile * 100))
    fig2.update_layout(paper_bgcolor=bgcolor)

    # Open chart
    fig3.add_trace(go.Scatter(x=df['date'], y=df['open'], line=actual_style, name='actual open'))
    fig3.add_trace(go.Scatter(x=df['date'], y=df['open_forecast'], line=forecast_style, name='forecast open'))
    fig3.add_trace(
        go.Scatter(x=df['date'], y=df['op_confidence_upper_band'], line=conf_style, name='upper confidence'))
    fig3.add_trace(
        go.Scatter(x=df['date'], y=df['op_confidence_lower_band'], line=conf_style, name='lower confidence'))
    fig3.add_hline(y=df['open'].quantile(quantile), line=quantile_style,
                   name='{}th percentile'.format(quantile * 100))
    fig3.update_layout(paper_bgcolor=bgcolor)

    # some styling stuff
    app = dash.Dash()
    layout = html.Div(children=[
        html.Div([
            html.H1(children='Time series Anomaly Analysis'),
            html.Div(children='Chart 1: Candlestick Chart'),
            dcc.Graph(
                id='candlestick1',
                figure=fig0)
        ]),
        html.Div([
            html.Div(children='Chart 2: Volumes Forecast Chart', style=page_style),
            dcc.Graph(id='volume_forecast_chart', figure=fig1)
        ]),
        html.Div([
            html.Div(children='Chart 3: Open Values Forecast Chart', style=page_style),
            dcc.Graph(id='open_forecast_chart', figure=fig3)
        ]),
        html.Div([
            html.Div(children='Chart 4: Close Forecast Chart', style=page_style),
            dcc.Graph(id='close_forecast_chart', figure=fig2),

        ])
    ],
        style=page_style)

    # run dash app to show charts
    app.layout = layout
    app.run_server(address, port)

