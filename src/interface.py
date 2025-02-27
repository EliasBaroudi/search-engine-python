import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output, State
import pandas as pd

# Initialisations
from main import *

collection = init(50) # On veut 50 CVE par API
corpus = get_corpus(collection)
search = get_engine(corpus)

app = dash.Dash(__name__)

# Ajout des polices dans le header
app.index_string = '''
<!DOCTYPE html>
<html>
    <head>
        {%metas%}
        <title>{%title%}</title>
        {%favicon%}
        {%css%}
        <style>
            * {
                font-family: 'Inter', sans-serif;
            }
            h1, h2, h3, h4, h5, h6 {
                font-family: 'Poppins', sans-serif;
            }
        </style>
    </head>
    <body>
        {%app_entry%}
        <footer>
            {%config%}
            {%scripts%}
            {%renderer%}
        </footer>
    </body>
</html>
'''

# Layout de l'application
app.layout = html.Div([
    # En-tête
    html.Div([
        html.H1("SecuPapers", className='header-title'),
        html.P("Recherchez des vulnérabilités avec leurs articles scientifiques associés", 
               className='header-subtitle')
    ], className='header-container'),

    # Zone de recherche 
    html.Div([
        html.Div([
            # Champ de texte
            dcc.Input(
                id="champ_texte",
                type="text",
                placeholder="Entrez des mots-clés de recherche...",
                className='search-input'
            )
        ], style={'width': '60%', 'display': 'inline-block'}),
        
        # Selection du nombre de documents
        html.Div([
            # Texte indicatif
            html.Label(
                "Nombre de résultats:",
                className='slider-label'
            ),

            # Barre coulissante
            dcc.Slider(
                id='slider',
                min=1,
                max=50,
                step=1,
                value=5,
                marks={i: str(i) for i in range(0, 51, 10)},
                tooltip={'placement': 'bottom', 'always_visible': True}
            )
        ], style={'width': '25%', 'display': 'inline-block', 'verticalAlign': 'top', 'marginLeft': '20px'}),
        
        # Bouton 'Rechercher'
        html.Button(
            "Rechercher",
            id="bouton",
            n_clicks=0,
            className='search-button'
        ),

        # Zone des filtres
        html.Div([
        html.Label("Source:", className='filter-label'),
        dcc.Checklist(
            id='source-filters',
            options=[
                {'label': 'NST', 'value': 'NST'},
                {'label': 'Kevin', 'value': 'Kevin'}
            ],
            value=['Kevin'],
            className='filter-options',
            inputClassName='checkbox-item',
            labelClassName='checkbox-label'
        )
        ], className='filter-section'),

        # Filtre pour les articles scientifiques
        html.Div([
        html.Label("Articles:", className='filter-label'),
        dcc.Checklist(
            id='articles-filter',
            options=[
                {'label': 'Uniquement les CVE avec articles scientifiques', 'value': True}
            ],
            value=[],
            className='filter-options',
            inputClassName='checkbox-item',
            labelClassName='checkbox-label'
        )
        ], className='filter-section')

    ], className='search-container'),

    # Statistiques de recherche
    html.Div(id='search-stats', className='search-stats', style={'display': 'none'}),

    # Zone de résultats
    html.Div(id='results-section'),

], style={'padding': '2rem', 'maxWidth': '1200px', 'margin': '0 auto'})

# Callback
@app.callback(
    [Output('results-section', 'children'),
     Output('search-stats', 'children'),
     Output('search-stats', 'style')],
    [Input('bouton', 'n_clicks'),
     Input('champ_texte', 'n_submit')],
    [State('champ_texte', 'value'),
     State('slider', 'value'),
     State('source-filters', 'value'),
     State('articles-filter', 'value')]
)
def execute_search(n_clicks, n_submit, text_value, slider_value, source_filters, articles_filter):
    if (n_clicks == 0 and n_submit is None) or not text_value:
        return html.Div(), "", {'display': 'none'}
    
    try:
        results = search.search(text_value, slider_value, source_filters, articles_filter).to_dict('records')
        
        stats_style = {
            'display': 'block'
        }
        stats = f"Trouvé {len(results)} résultat{'s' if len(results) > 1 else ''} pour '{text_value}'"
        
        result_cards = []
        for result in results:
            card = html.Div([
                # En-tête de la carte
                html.Div([
                    # Nom + ID
                    html.Div([
                        # ID de CVE
                        html.H3(result['CVE ID'], className='cve-id'),
                        # Nom de CVE
                        html.H4(result['Name'], className='cve-name'),
                        # Nom de la source
                        html.H4(f"Source : {result['Source']}", className='cve-source'),
                    ], style={'flex': '1'}),

                    # Score
                    html.Div([
                        html.Strong("Score: "),
                        html.Span(f"{result['Score']:.3f}", className='score-badge')
                    ], style={'marginLeft': '1rem'})
                ], className='card-header'),
                
                # Description
                html.Div(className='description', children=[
                    html.Strong("Description :", className='description-title'),
                    html.P(result['Description'], className='description-text')
                ]),
                
                # Liens et références
                html.Div([
                    #Liens CVE
                    html.Div([
                        html.Strong("Liens CVE :"),
                        html.Div([
                            html.A(
                                note.strip(),
                                href=note.strip(),
                                target="_blank",
                                className='link'
                            ) for note in result['CVE Link'].split('\n') if note.strip()
                        ])
                    ], style={'flex': '1'}),
                    
                    #Liens Arxiv
                    html.Div([
                        html.Strong("Articles Arxiv :"),
                        html.Div(
                            [html.A(
                                link,
                                href=link,
                                target="_blank",
                                className='link'
                            ) for link in (result['Arxiv related'] if isinstance(result['Arxiv related'], list) else [])]
                            if result['Arxiv related'] != 'Aucun article'
                            else html.P("Aucun article trouvé", className='no-articles')
                        )
                    ], style={'flex': '1'})
                ], className='links-section')
            ], className='result-card')
            result_cards.append(card)
        
        return html.Div(result_cards), stats, stats_style
        
    except Exception as e:
        error_div = html.Div([
            html.Div(
                f"Une erreur s'est produite: {str(e)}",
                className='error-message'
            )
        ])
        return error_div, "", {'display': 'none'}

if __name__ == '__main__':
    app.run_server(debug=True)