using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using Windows.Security.Authentication.Web;
using Windows.Storage.Pickers;
using Windows.UI.Popups;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;

// Pour plus d'informations sur le modèle d'élément Page vierge, consultez la page http://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409

namespace Epicture
{
    public class MenuItem
    {
        public string Name { get; set; }
        public string IdPhoto { get; set; }
    }

    /// <summary>
    ///     Une page vide peut être utilisée seule ou constituer une page de destination au sein d'un frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        private readonly ObservableCollection<MenuItem> _ifavItems = new ObservableCollection<MenuItem>();
        private readonly ObservableCollection<MenuItem> _items = new ObservableCollection<MenuItem>();
        private readonly ImageDownloader downloader = new ImageDownloader();
        public FlickrAuth flickr;
        private bool IsFavButtonPressed;
        private bool IsLoggedFlickr;
        private FlickrAuth.RootObject res = new FlickrAuth.RootObject();


        private MenuItem toto;

        public MainPage()
        {
            InitializeComponent();
            UploadButton.Visibility = Visibility.Collapsed;
            DeleteButton.Visibility = Visibility.Collapsed;
            FavButton.Visibility = Visibility.Collapsed;
            FavDisplay.Visibility = Visibility.Collapsed;
            DeleteFavButton.Visibility = Visibility.Collapsed;
        }

        /// <summary>
        ///     Log Flickr OnClick Button
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private async void Flickr_Log_Click(object sender, RoutedEventArgs e)
        {
            if (IsLoggedFlickr)
            {
                var msg = new MessageDialog("Vous êtes déja Connecté");
                await msg.ShowAsync();
            }
            else
            {
                string output;
                flickr = new FlickrAuth();
                var callback = new Uri("http://www.example.com/");
                var FlickrUri = new Uri(await flickr.GetLonginLink());
                try
                {
                    var webAuthenticationResult = await WebAuthenticationBroker.AuthenticateAsync(
                        WebAuthenticationOptions.None,
                        FlickrUri, callback);
                    if (webAuthenticationResult.ResponseStatus == WebAuthenticationStatus.Success)
                    {
                        output = webAuthenticationResult.ResponseData;
                        await flickr.GetAccessToken(output);
                        await flickr.FlickrOAuthRequest();
                        res = await flickr.GetPublicPhoto();

                        AdaptiveGridViewControl.ItemsSource = await downloader.DownloadImageFlickr(res, null, _items,
                            _ifavItems, IsFavButtonPressed);
                        IsLoggedFlickr = true;
                        makeButtonVisible();
                    }
                    else if (webAuthenticationResult.ResponseStatus == WebAuthenticationStatus.ErrorHttp)
                    {
                        output = "HTTP Error returned by AuthenticateAsync() : " +
                                 webAuthenticationResult.ResponseErrorDetail;
                    }
                    else if (webAuthenticationResult.ResponseStatus == WebAuthenticationStatus.UserCancel)
                    {
                        output = "Authentication process was cancelled by the user";
                    }
                }
                catch (Exception exception)
                {
                    var msg_dialog = new MessageDialog(exception.Message);
                    await msg_dialog.ShowAsync();
                }
            }
        }


        private async void UploadButton_Click(object sender, RoutedEventArgs e)
        {
            // Permet de Pick une Image en générant 
            // une boite de dialogue
            // /!\ Ne prenez pas des photos de vos images, Bureau etc..
            // Prenez a aprtir du AppData/Local/Package/9f3d1843-4a64-4da7-a30f-c7fc1df2f7e8_nqw117v1ny6wy/LocalState
            // mettez vos photos dans ce dossier
            var picker = new FileOpenPicker
            {
                ViewMode = PickerViewMode.Thumbnail,
                SuggestedStartLocation = PickerLocationId.PicturesLibrary
            };
            picker.FileTypeFilter.Add(".jpg");

            var file = await picker.PickSingleFileAsync();

            if (file != null)
            {
                Stream fs = new FileStream(file.Path, FileMode.Open, FileAccess.Read);
                var fileName = Path.GetFileName(file.Path);
                if (IsLoggedFlickr)
                {
                    var res_upload = await flickr.UploadPhotoFlickr(fs, fileName);
                    if (res_upload == "ok")
                    {
                        res = await flickr.GetPublicPhoto();
                        _items.Clear();
                        AdaptiveGridViewControl.ItemsSource = await downloader.DownloadImageFlickr(res, null, _items,
                            _ifavItems, IsFavButtonPressed);
                    }
                }
                // Implémenter Upload pour ImGur
            }
        }

        private async void Bouton_ImGur_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var webAuthenticationResult = await WebAuthenticationBroker.AuthenticateAsync(
                    WebAuthenticationOptions.None,
                    new Uri("https://api.imgur.com/oauth2/authorize?client_id=bcef5309ee7a60e&response_type=token"),
                    new Uri("http://www.example.com/"));
                if (webAuthenticationResult.ResponseStatus == WebAuthenticationStatus.Success)
                {
                    var output = webAuthenticationResult.ResponseData;
                }
            }
            catch (Exception exception)
            {
                var msg = new MessageDialog(exception.Message);
                await msg.ShowAsync();
            }
        }

        private void AdaptiveGridViewControl_ItemClick(object sender, ItemClickEventArgs e)
        {
            if (e.ClickedItem != null)
                toto = e.ClickedItem as MenuItem;
        }

        private void AdaptiveGridViewControl_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
        }

        private void FavButton_Click(object sender, RoutedEventArgs e)
        {
            //flickr.AddToFav(toto.IdPhoto);
        }

        private async void ToggleButton_Checked(object sender, RoutedEventArgs e)
        {
            var res = await flickr.GetPublicFav();

            IsFavButtonPressed = true;
            if (res.Stat == "ok")
            {
                AdaptiveGridViewControl.ItemsSource = await downloader.DownloadImageFlickr(res, null, _items, _ifavItems,
                    IsFavButtonPressed);
                DeleteFavButton.Visibility = Visibility.Visible;
            }
        }

        private void makeButtonVisible()
        {
            UploadButton.Visibility = Visibility.Visible;
            DeleteButton.Visibility = Visibility.Visible;
            FavButton.Visibility = Visibility.Visible;
            FavDisplay.Visibility = Visibility.Visible;
        }

        private void FavDisplay_Unchecked(object sender, RoutedEventArgs e)
        {
            DeleteFavButton.Visibility = Visibility.Collapsed;
            
            var itemMenu = _items.ToList();
            var itemMenuFav = _ifavItems.ToList();

            foreach (var menuItem in itemMenuFav)
            foreach (var item in itemMenu)
                if (item.IdPhoto == menuItem.IdPhoto)
                    _items.Remove(item);

            AdaptiveGridViewControl.ItemsSource = _items;
            _ifavItems.Clear();
        }

        private async void DeleteButton_Click(object sender, RoutedEventArgs e)
        {
            if (toto != null)
            {
                var is_delete = await flickr.deleteImageFlicr(toto.IdPhoto);
                if (is_delete == "ok")
                {
                    var msg = new MessageDialog("Photo Supprimer");
                    await msg.ShowAsync();
                }
                else
                {
                    var msg = new MessageDialog("Un problème est survenu lors de la suppression");
                    await msg.ShowAsync();
                    return;
                }
                _items.Clear();
                res = await flickr.GetPublicPhoto();
                AdaptiveGridViewControl.ItemsSource = await downloader.DownloadImageFlickr(res, null, _items, _ifavItems,
                    IsFavButtonPressed);
            }
        }

        private async void DeleteFavButton_Click(object sender, RoutedEventArgs e)
        {
            if (toto != null && _ifavItems.Count > 0)
            {
                foreach (var ifavItem in _ifavItems)
                {
                    if (ifavItem.IdPhoto == toto.IdPhoto)
                    {
                      _ifavItems.Clear();
                        _items.Clear();
                        break;
                    }
                }
                var result_del = await flickr.DeleteFav(toto.IdPhoto);
                if (result_del == "ok")
                {
                    res = await flickr.GetPublicFav();
                    AdaptiveGridViewControl.ItemsSource = await downloader.DownloadImageFlickr(res, null, _items, _ifavItems,
                      IsFavButtonPressed);
                    MessageDialog msg_ok = new MessageDialog("Votre photo a bien été supprimé des favoris");
                    await msg_ok.ShowAsync();
                }
                else
                {
                    MessageDialog msg_failure = new MessageDialog("La suppresion de l'une de vos photos faovrites a rencontrées un problèmes");
                    await msg_failure.ShowAsync();
                }
            }
        }
    }
}